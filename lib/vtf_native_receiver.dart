import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

class VtfTransferState {
  final String artifactSha;
  final int completedSegments;
  final int totalSegments;
  final int receivedBytes;
  final int totalBytes;
  final bool verified;

  const VtfTransferState(
    this.artifactSha,
    this.completedSegments,
    this.totalSegments,
    this.receivedBytes,
    this.totalBytes,
    this.verified,
  );

  double get progress => totalBytes == 0 ? 0 : receivedBytes / totalBytes;
}

class VtfNativeReceiver {
  static const api =
      'https://ihrocbdgtfblfsifaiwk.supabase.co/functions/v1/vtf-bootstrap';
  static const bootstrapVersion = 'VTF_SEGMENT_BOOTSTRAP_V8';

  static const _workerOptions = <int>[3, 4, 5, 6];
  static const _progressInterval = Duration(milliseconds: 150);
  static const _minimumLearningBytes = 8 * 1024 * 1024;

  final Dio _dio = Dio();
  final HttpClient _httpClient = HttpClient()
    ..maxConnectionsPerHost = 8
    ..idleTimeout = const Duration(seconds: 30);

  DateTime _lastProgressEmit = DateTime.fromMillisecondsSinceEpoch(0);
  int _runReconnects = 0;

  Future<Directory> _dir(String artifactSha) async => Directory(
        '${(await getApplicationSupportDirectory()).path}/vtf/$artifactSha',
      )..createSync(recursive: true);

  Future<File> finalFile() async => File(
        '${(await getDownloadsDirectory())?.path ?? (await getApplicationSupportDirectory()).path}/'
        'VERA_HOME_VERIFIED.apk',
      );

  Future<VtfTransferState> run({
    required void Function(VtfTransferState) onProgress,
    String? expectedSha,
  }) async {
    if (expectedSha != null && !_isSha256(expectedSha)) {
      throw StateError('Invalid expected artifact SHA');
    }

    final response = await _dio.post(
      api,
      options: Options(
        headers: expectedSha == null
            ? null
            : {'x-vtf-artifact-sha256': expectedSha},
        validateStatus: (status) =>
            status != null && status >= 200 && status < 500,
      ),
    );
    final data =
        response.data is String ? jsonDecode(response.data) : response.data;

    if (response.statusCode != 200) {
      final error = data is Map ? data['error'] : null;
      throw StateError(
        'Bootstrap failed: ${response.statusCode} ${error ?? 'UNKNOWN'}',
      );
    }

    if (data is! Map ||
        data['version'] != bootstrapVersion ||
        !_isSha256(data['sha256']) ||
        data['bytes'] is! int ||
        (data['bytes'] as int) <= 0 ||
        data['segments'] is! List) {
      throw StateError('Artifact binding failed');
    }

    final artifactSha = data['sha256'] as String;
    final totalBytes = data['bytes'] as int;
    if (expectedSha != null && artifactSha != expectedSha) {
      throw StateError('Artifact capability changed');
    }

    final dir = await _dir(artifactSha);
    final prefs = await SharedPreferences.getInstance();
    final segments = List<Map<String, dynamic>>.from(data['segments'] as List)
      ..sort((a, b) => (a['index'] as int).compareTo(b['index'] as int));

    _validateManifest(segments, totalBytes);

    final initialReceivedBytes = await _receivedBytes(segments, dir);
    final workerCount = _selectWorkerCount(prefs);
    final transferStartedAt = DateTime.now();
    _lastProgressEmit = DateTime.fromMillisecondsSinceEpoch(0);
    _runReconnects = 0;

    final out = await finalFile();
    if (await _wholeFileValid(out, artifactSha, totalBytes)) {
      final state = VtfTransferState(
        artifactSha,
        segments.length,
        segments.length,
        totalBytes,
        totalBytes,
        true,
      );
      onProgress(state);
      return state;
    }

    var cursor = 0;

    Future<void> worker() async {
      while (true) {
        final slot = cursor++;
        if (slot >= segments.length) return;

        final segment = segments[slot];
        final index = segment['index'] as int;
        final file = File(
          '${dir.path}/segment-${index.toString().padLeft(4, '0')}.bin',
        );

        if (!await _segmentValid(file, segment)) {
          if (await file.exists()) {
            await file.delete();
          }
          await _downloadSegment(
            artifactSha: artifactSha,
            totalBytes: totalBytes,
            segment: segment,
            file: file,
            segments: segments,
            dir: dir,
            onProgress: onProgress,
          );
        }

        await prefs.setBool('vtf:$artifactSha:$index:done', true);
        await _emit(
          artifactSha,
          totalBytes,
          segments,
          dir,
          onProgress,
        );
      }
    }

    await Future.wait(
      List<Future<void>>.generate(workerCount, (_) => worker()),
    );

    final staging = File('${out.path}.part');
    if (await staging.exists()) {
      await staging.delete();
    }
    if (await out.exists()) {
      await out.delete();
    }

    final sink = staging.openWrite();
    try {
      for (final segment in segments) {
        final index = segment['index'] as int;
        final file = File(
          '${dir.path}/segment-${index.toString().padLeft(4, '0')}.bin',
        );
        if (!await _segmentValid(file, segment)) {
          throw StateError('Segment $index lost verification before assembly');
        }
        await sink.addStream(file.openRead());
      }
      await sink.flush();
    } finally {
      await sink.close();
    }

    if (!await _wholeFileValid(staging, artifactSha, totalBytes)) {
      if (await staging.exists()) {
        await staging.delete();
      }
      throw StateError('Whole-file verification failed');
    }

    await staging.rename(out.path);
    await prefs.setBool('vtf:$artifactSha:verified', true);

    final transferredBytes =
        (totalBytes - initialReceivedBytes).clamp(0, totalBytes);
    await _learnFromVerifiedTransfer(
      prefs: prefs,
      workerCount: workerCount,
      transferredBytes: transferredBytes,
      elapsed: DateTime.now().difference(transferStartedAt),
    );

    final state = VtfTransferState(
      artifactSha,
      segments.length,
      segments.length,
      totalBytes,
      totalBytes,
      true,
    );
    onProgress(state);
    return state;
  }

  bool _isSha256(Object? value) =>
      value is String && RegExp(r'^[0-9a-f]{64}$').hasMatch(value);

  void _validateManifest(
    List<Map<String, dynamic>> segments,
    int totalBytes,
  ) {
    if (segments.isEmpty) {
      throw StateError('Manifest contains no segments');
    }

    var summedBytes = 0;
    for (var i = 0; i < segments.length; i++) {
      final segment = segments[i];
      if (segment['index'] != i ||
          segment['bytes'] is! int ||
          !_isSha256(segment['sha256']) ||
          segment['signed_url'] is! String ||
          (segment['signed_url'] as String).isEmpty) {
        throw StateError('Invalid segment manifest at index $i');
      }
      final bytes = segment['bytes'] as int;
      if (bytes <= 0) {
        throw StateError('Invalid segment length at index $i');
      }
      summedBytes += bytes;
    }

    if (summedBytes != totalBytes) {
      throw StateError('Manifest byte total mismatch');
    }
  }

  Future<void> _downloadSegment({
    required String artifactSha,
    required int totalBytes,
    required Map<String, dynamic> segment,
    required File file,
    required List<Map<String, dynamic>> segments,
    required Directory dir,
    required void Function(VtfTransferState) onProgress,
  }) async {
    final index = segment['index'] as int;
    final expectedBytes = segment['bytes'] as int;
    final signedUrl = segment['signed_url'] as String;
    final partial = File('${file.path}.part');

    if (await _segmentValid(partial, segment)) {
      await partial.rename(file.path);
      return;
    }

    var start = await partial.exists() ? await partial.length() : 0;
    if (start > expectedBytes) {
      await partial.delete();
      start = 0;
    }

    Future<void> downloadFrom(int offset) async {
      RandomAccessFile? raf;
      try {
        final request = await _httpClient.getUrl(Uri.parse(signedUrl));
        request.headers.set(HttpHeaders.acceptEncodingHeader, 'identity');
        if (offset > 0) {
          request.headers.set(HttpHeaders.rangeHeader, 'bytes=$offset-');
        }

        final response = await request.close();
        final status = response.statusCode;
        final contentRange = response.headers.value(HttpHeaders.contentRangeHeader);

        if (offset > 0) {
          final rangeAccepted = status == HttpStatus.partialContent &&
              contentRange != null &&
              contentRange.startsWith('bytes $offset-');
          if (!rangeAccepted) {
            await response.drain<void>();
            throw StateError(
              'Segment $index resume rejected: status=$status '
              'content-range=${contentRange ?? 'missing'}',
            );
          }
        } else if (status != HttpStatus.ok &&
            status != HttpStatus.partialContent) {
          final body = await utf8.decoder.bind(response).join();
          throw StateError(
            'Segment $index transfer failed: HTTP $status '
            '${body.length > 240 ? body.substring(0, 240) : body}',
          );
        }

        raf = await partial.open(
          mode: offset > 0 ? FileMode.append : FileMode.write,
        );

        await for (final chunk in response) {
          await raf.writeFrom(chunk);
          await _emitThrottled(
            artifactSha,
            totalBytes,
            segments,
            dir,
            onProgress,
          );
        }
        await raf.flush();
      } finally {
        await raf?.close();
      }
    }

    const maxReconnects = 4;
    var reconnects = 0;
    var usedRangeFallback = false;

    while (true) {
      final offset = await partial.exists() ? await partial.length() : 0;
      if (offset == expectedBytes) break;
      if (offset > expectedBytes) {
        throw StateError(
          'Segment $index exceeded expected size: $offset/$expectedBytes',
        );
      }

      final before = offset;
      try {
        await downloadFrom(offset);
      } on StateError {
        if (offset == 0 || usedRangeFallback) rethrow;
        if (await partial.exists()) {
          await partial.delete();
        }
        usedRangeFallback = true;
        continue;
      } on HttpException {
        final after = await partial.exists() ? await partial.length() : 0;
        if (after == expectedBytes) break;
        if (after <= before || reconnects >= maxReconnects) rethrow;
        reconnects++;
        _runReconnects++;
        continue;
      } on SocketException {
        final after = await partial.exists() ? await partial.length() : 0;
        if (after == expectedBytes) break;
        if (after <= before || reconnects >= maxReconnects) rethrow;
        reconnects++;
        _runReconnects++;
        continue;
      }

      final after = await partial.exists() ? await partial.length() : 0;
      if (after == expectedBytes) break;
      if (after <= before) {
        throw StateError(
          'Segment $index transfer stalled at $after/$expectedBytes',
        );
      }
      if (reconnects >= maxReconnects) {
        throw StateError(
          'Segment $index incomplete after reconnects: '
          '$after/$expectedBytes',
        );
      }
      reconnects++;
      _runReconnects++;
    }

    await _emitThrottled(
      artifactSha,
      totalBytes,
      segments,
      dir,
      onProgress,
      force: true,
    );

    if (!await _segmentValid(partial, segment)) {
      if (await partial.exists()) {
        await partial.delete();
      }
      throw StateError('Segment $index verification failed');
    }

    await partial.rename(file.path);
  }

  Future<bool> _segmentValid(
    File file,
    Map<String, dynamic> segment,
  ) async {
    if (!await file.exists()) return false;

    final expectedBytes = segment['bytes'];
    final expectedSha = segment['sha256'];
    if (expectedBytes is! int || expectedSha is! String) return false;
    if (await file.length() != expectedBytes) return false;

    final digest = await sha256.bind(file.openRead()).first;
    return digest.toString() == expectedSha;
  }

  Future<bool> _wholeFileValid(
    File file,
    String expectedSha,
    int expectedBytes,
  ) async {
    if (!await file.exists()) return false;
    if (await file.length() != expectedBytes) return false;

    final digest = await sha256.bind(file.openRead()).first;
    return digest.toString() == expectedSha;
  }

  Future<int> _receivedBytes(
    List<Map<String, dynamic>> segments,
    Directory dir,
  ) async {
    var bytes = 0;
    for (final segment in segments) {
      final index = segment['index'] as int;
      final expectedBytes = segment['bytes'] as int;
      final file = File(
        '${dir.path}/segment-${index.toString().padLeft(4, '0')}.bin',
      );
      final partial = File('${file.path}.part');

      if (await file.exists()) {
        final length = await file.length();
        bytes += length > expectedBytes ? expectedBytes : length;
      } else if (await partial.exists()) {
        final length = await partial.length();
        bytes += length > expectedBytes ? expectedBytes : length;
      }
    }
    return bytes;
  }

  int _selectWorkerCount(SharedPreferences prefs) {
    for (final workers in _workerOptions) {
      final samples = prefs.getInt('vtf:optimizer:samples:$workers') ?? 0;
      if (samples == 0) return workers;
    }

    final totalSamples = _workerOptions.fold<int>(
      0,
      (sum, workers) =>
          sum + (prefs.getInt('vtf:optimizer:samples:$workers') ?? 0),
    );

    if (totalSamples > 0 && totalSamples % 8 == 0) {
      return _workerOptions[(totalSamples ~/ 8) % _workerOptions.length];
    }

    var bestWorkers = _workerOptions.first;
    var bestScore = -1.0;
    for (final workers in _workerOptions) {
      final score = prefs.getDouble('vtf:optimizer:score:$workers') ?? 0.0;
      if (score > bestScore) {
        bestScore = score;
        bestWorkers = workers;
      }
    }
    return bestWorkers;
  }

  Future<void> _learnFromVerifiedTransfer({
    required SharedPreferences prefs,
    required int workerCount,
    required int transferredBytes,
    required Duration elapsed,
  }) async {
    if (transferredBytes < _minimumLearningBytes ||
        elapsed.inMilliseconds <= 0) {
      return;
    }

    final seconds = elapsed.inMilliseconds / 1000.0;
    final bytesPerSecond = transferredBytes / seconds;
    final reliabilityPenalty = 1.0 + (_runReconnects * 0.05);
    final score = bytesPerSecond / reliabilityPenalty;

    final samplesKey = 'vtf:optimizer:samples:$workerCount';
    final scoreKey = 'vtf:optimizer:score:$workerCount';
    final samples = prefs.getInt(samplesKey) ?? 0;
    final oldScore = prefs.getDouble(scoreKey);
    final learnedScore =
        oldScore == null ? score : (oldScore * 0.70) + (score * 0.30);

    await prefs.setInt(samplesKey, samples + 1);
    await prefs.setDouble(scoreKey, learnedScore);
    await prefs.setInt('vtf:optimizer:last_workers', workerCount);
    await prefs.setDouble('vtf:optimizer:last_bps', bytesPerSecond);
    await prefs.setInt('vtf:optimizer:last_reconnects', _runReconnects);
  }

  Future<void> resetTransferDataPreserveLearning(String artifactSha) async {
    if (!_isSha256(artifactSha)) {
      throw StateError('Invalid artifact SHA for reset');
    }

    final dir = await _dir(artifactSha);
    if (await dir.exists()) {
      await dir.delete(recursive: true);
    }

    final out = await finalFile();
    if (await out.exists()) {
      await out.delete();
    }
    final staging = File('${out.path}.part');
    if (await staging.exists()) {
      await staging.delete();
    }

    final prefs = await SharedPreferences.getInstance();
    final keys = prefs.getKeys().where((key) =>
        key.startsWith('vtf:$artifactSha:') &&
        !key.startsWith('vtf:optimizer:'));
    for (final key in keys.toList()) {
      await prefs.remove(key);
    }
  }

  Future<String> optimizerSummary() async {
    final prefs = await SharedPreferences.getInstance();
    final nextWorkers = _selectWorkerCount(prefs);
    final lastWorkers = prefs.getInt('vtf:optimizer:last_workers');
    final lastBps = prefs.getDouble('vtf:optimizer:last_bps');
    final reconnects = prefs.getInt('vtf:optimizer:last_reconnects') ?? 0;
    return 'next_workers=$nextWorkers '
        'last_workers=${lastWorkers ?? 'none'} '
        'last_bps=${lastBps?.toStringAsFixed(0) ?? 'none'} '
        'last_reconnects=$reconnects';
  }

  Future<void> _emitThrottled(
    String artifactSha,
    int totalBytes,
    List<Map<String, dynamic>> segments,
    Directory dir,
    void Function(VtfTransferState) callback, {
    bool force = false,
  }) async {
    final now = DateTime.now();
    if (!force &&
        now.difference(_lastProgressEmit) < _progressInterval) {
      return;
    }
    _lastProgressEmit = now;
    await _emit(
      artifactSha,
      totalBytes,
      segments,
      dir,
      callback,
    );
  }

  Future<void> _emit(
    String artifactSha,
    int totalBytes,
    List<Map<String, dynamic>> segments,
    Directory dir,
    void Function(VtfTransferState) callback,
  ) async {
    var bytes = 0;
    var done = 0;

    for (final segment in segments) {
      final index = segment['index'] as int;
      final expectedBytes = segment['bytes'] as int;
      final file = File(
        '${dir.path}/segment-${index.toString().padLeft(4, '0')}.bin',
      );
      final partial = File('${file.path}.part');

      if (await file.exists() && await file.length() == expectedBytes) {
        bytes += expectedBytes;
        done++;
      } else if (await partial.exists()) {
        final partialBytes = await partial.length();
        bytes += partialBytes > expectedBytes ? expectedBytes : partialBytes;
      }
    }

    callback(
      VtfTransferState(
        artifactSha,
        done,
        segments.length,
        bytes,
        totalBytes,
        false,
      ),
    );
  }
}
