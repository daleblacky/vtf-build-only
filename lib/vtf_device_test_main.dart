import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import 'vtf_native_receiver.dart';

void main() => runApp(const VtfDeviceHarnessApp());

class VtfDeviceHarnessApp extends StatelessWidget {
  const VtfDeviceHarnessApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'VTF PR44 Device Harness',
      theme: ThemeData.dark(useMaterial3: true),
      home: const VtfHarnessScreen(),
    );
  }
}

class VtfHarnessScreen extends StatefulWidget {
  const VtfHarnessScreen({super.key});

  @override
  State<VtfHarnessScreen> createState() => _VtfHarnessScreenState();
}

class _VtfHarnessScreenState extends State<VtfHarnessScreen> {
  final _receiver = VtfNativeReceiver();
  final List<Map<String, dynamic>> _events = [];
  VtfTransferState? _state;
  bool _busy = false;
  bool _receiptLoaded = false;
  int _lastRecordedCompletedSegments = -1;
  String _status = 'Ready';
  String _optimizer = 'optimizer: awaiting verified sample';

  Future<File?> _receiptFile() async {
    final downloads = await getDownloadsDirectory();
    if (downloads == null) return null;
    return File('${downloads.path}/VTF_PR44_DEVICE_RECEIPT.json');
  }

  Future<void> _loadReceiptOnce() async {
    if (_receiptLoaded) return;
    _receiptLoaded = true;
    final receipt = await _receiptFile();
    if (receipt == null || !await receipt.exists()) return;
    try {
      final decoded = jsonDecode(await receipt.readAsString());
      if (decoded is Map && decoded['events'] is List) {
        _events.addAll(
          (decoded['events'] as List)
              .whereType<Map>()
              .map((e) => Map<String, dynamic>.from(e)),
        );
      }
    } catch (_) {
      _events.add({
        'at': DateTime.now().toUtc().toIso8601String(),
        'event': 'PRIOR_RECEIPT_UNREADABLE',
        'detail': '',
      });
    }
  }

  Future<void> _record(String event, [String detail = '']) async {
    await _loadReceiptOnce();
    _events.add({
      'at': DateTime.now().toUtc().toIso8601String(),
      'event': event,
      'detail': detail,
    });
    final receipt = await _receiptFile();
    if (receipt == null) return;
    await receipt.writeAsString(jsonEncode({
      'version': 'VTF_PR44_DEVICE_HARNESS_V2',
      'artifact_sha': _state?.artifactSha,
      'artifact_bytes': _state?.totalBytes,
      'events': _events,
    }));
  }

  void _observe(VtfTransferState s) {
    if (!mounted) return;
    setState(() => _state = s);
    if (s.completedSegments != _lastRecordedCompletedSegments) {
      _lastRecordedCompletedSegments = s.completedSegments;
      unawaited(
        _record(
          'PROGRESS',
          'sha=${s.artifactSha} completed=${s.completedSegments}/'
          '${s.totalSegments} bytes=${s.receivedBytes}/${s.totalBytes} '
          'verified=${s.verified}',
        ),
      );
    }
  }

  Future<void> _runReceiver() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _status = 'Running';
    });
    await _record('RUN_START');
    try {
      final state = await _receiver.run(onProgress: _observe);
      final optimizer = await _receiver.optimizerSummary();
      if (mounted) {
        setState(() => _optimizer = 'optimizer: $optimizer');
      }
      await _record(
        'RUN_VERIFIED',
        'sha=${state.artifactSha} bytes=${state.totalBytes} '
        'optimizer={$optimizer}',
      );
      if (mounted) {
        setState(() {
          _state = state;
          _status = 'Verified';
        });
      }
    } catch (e) {
      await _record('RUN_FAILED', e.toString());
      if (mounted) setState(() => _status = 'Failed: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<File?> _segment0() async {
    final sha = _state?.artifactSha;
    if (sha == null) return null;
    final support = await getApplicationSupportDirectory();
    return File('${support.path}/vtf/$sha/segment-0000.bin');
  }

  Future<void> _prepareCorruptSegmentTest() async {
    if (_busy) return;
    final segment = await _segment0();
    final out = await _receiver.finalFile();
    if (segment == null || !await segment.exists()) {
      setState(() => _status = 'No completed segment 0 yet');
      return;
    }
    if (await out.exists()) await out.delete();

    final bytes = await segment.readAsBytes();
    if (bytes.isEmpty) {
      setState(() => _status = 'Segment 0 is empty');
      return;
    }
    bytes[0] = bytes[0] ^ 0xFF;
    await segment.writeAsBytes(bytes, flush: true);

    await _record(
      'CORRUPT_SEGMENT_0_PREPARED',
      'sha=${_state?.artifactSha}',
    );
    setState(() => _status = 'Segment 0 corrupted; tap Start / Resume');
  }

  Future<void> _duplicateNoChange() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _status = 'Duplicate test running';
    });
    try {
      final first = await _receiver.run(onProgress: _observe);
      final out = await _receiver.finalFile();
      final before = (await sha256.bind(out.openRead()).first).toString();

      final second = await _receiver.run(
        expectedSha: first.artifactSha,
        onProgress: _observe,
      );
      final after = (await sha256.bind(out.openRead()).first).toString();

      final pass = before == after &&
          after == first.artifactSha &&
          second.artifactSha == first.artifactSha;
      await _record(
        pass ? 'DUPLICATE_NO_CHANGE_PASS' : 'DUPLICATE_NO_CHANGE_FAIL',
        'before=$before after=$after sha=${first.artifactSha}',
      );
      if (mounted) {
        setState(() {
          _state = second;
          _status =
              pass ? 'Duplicate no-change PASS' : 'Duplicate test FAIL';
        });
      }
    } catch (e) {
      await _record('DUPLICATE_TEST_FAILED', e.toString());
      if (mounted) {
        setState(() => _status = 'Duplicate test failed: $e');
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _resetTransferPreserveLearning() async {
    if (_busy) return;
    final sha = _state?.artifactSha;
    if (sha == null) {
      setState(() => _status = 'No artifact SHA yet');
      return;
    }

    await _receiver.resetTransferDataPreserveLearning(sha);
    final optimizer = await _receiver.optimizerSummary();
    await _record(
      'TRANSFER_RESET_LEARNING_PRESERVED',
      'sha=$sha optimizer={$optimizer}',
    );
    if (mounted) {
      setState(() {
        _state = null;
        _optimizer = 'optimizer: $optimizer';
        _status = 'Transfer reset; learning preserved';
      });
    }
  }

  Future<void> _removeFinalOnly() async {
    if (_busy) return;
    final out = await _receiver.finalFile();
    if (await out.exists()) await out.delete();
    await _record(
      'FINAL_OUTPUT_REMOVED_ONLY',
      'sha=${_state?.artifactSha}',
    );
    setState(() => _status = 'Final removed; verified segments preserved');
  }

  @override
  Widget build(BuildContext context) {
    final s = _state;
    final progress = s?.progress ?? 0;
    return Scaffold(
      appBar: AppBar(title: const Text('VTF PR44 Device Harness')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text(_status, style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 12),
          LinearProgressIndicator(value: progress.clamp(0, 1).toDouble()),
          const SizedBox(height: 8),
          Text(
            s == null
                ? 'No transfer state yet'
                : '${s.completedSegments}/${s.totalSegments} segments • '
                  '${s.receivedBytes}/${s.totalBytes} bytes • '
                  'verified=${s.verified}\n'
                  'sha=${s.artifactSha}',
          ),
          const SizedBox(height: 8),
          Text(_optimizer),
          const SizedBox(height: 20),
          FilledButton(
            onPressed: _busy ? null : _runReceiver,
            child: const Text('Start / Resume'),
          ),
          const SizedBox(height: 10),
          OutlinedButton(
            onPressed: _busy ? null : _resetTransferPreserveLearning,
            child: const Text('Reset transfer data; preserve learning'),
          ),
          const SizedBox(height: 10),
          OutlinedButton(
            onPressed: _busy ? null : _removeFinalOnly,
            child: const Text('Remove final only; preserve segments'),
          ),
          const SizedBox(height: 10),
          OutlinedButton(
            onPressed: _busy ? null : _prepareCorruptSegmentTest,
            child: const Text('Prepare corrupt-segment test'),
          ),
          const SizedBox(height: 10),
          OutlinedButton(
            onPressed: _busy ? null : _duplicateNoChange,
            child: const Text('Run duplicate no-change test'),
          ),
          const SizedBox(height: 24),
          const Text(
            'Interruption/restart test: start transfer, close the app while '
            'bytes are moving, reopen it, then tap Start / Resume. The receiver '
            'must retain completed/partial evidence and resume missing bytes only.',
          ),
          const SizedBox(height: 12),
          const Text(
            'BOUNDARY_LOCK=ON • test package only • canonical bootstrap selects '
            'current artifact • receiver verifies every admitted segment',
          ),
        ],
      ),
    );
  }
}
