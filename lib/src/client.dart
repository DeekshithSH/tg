part of '../tg.dart';

class Client extends t.Client {
  Client({
    required this.receiver,
    required this.sender,
    required this.obfuscation,
    this.authKey
  });

  final Obfuscation obfuscation;
  final Stream<Uint8List> receiver;
  final Sink<List<int>> sender;

  final int sessionId = Random().nextInt(1 << 32);
  AuthorizationKey? authKey;

  late final _EncryptedTransformer _trns;

  final _idSeq = _MessageIdSequenceGenerator();

  //final Set<int> _msgsToAck = {};

  final Map<int, Completer<t.Result>> _pending = {};
  // final List<int> _msgsToAck = [];

  final _streamController = StreamController<UpdatesBase>.broadcast();

  Stream<UpdatesBase> get stream => _streamController.stream;

  void _handleIncomingMessage(TlObject msg) {
    if (msg is UpdatesBase) {
      _streamController.add(msg);
    }

    //
    if (msg is MsgContainer) {
      for (final message in msg.messages) {
        _handleIncomingMessage(message);
      }

      return;
    } else if (msg is Msg) {
      _handleIncomingMessage(msg.body);
      return;
    } else if (msg is BadMsgNotification) {
      final badMsgId = msg.badMsgId;
      final task = _pending[badMsgId];
      task?.completeError(BadMessageException._(msg));
      _pending.remove(badMsgId);
    } else if (msg is RpcResult) {
      final reqMsgId = msg.reqMsgId;
      final task = _pending[reqMsgId];

      final result = msg.result;

      if (result is RpcError) {
        task?.complete(t.Result.error(result));
        _pending.remove(reqMsgId);
        return;
      } else if (result is GzipPacked) {
        final gZippedData = GZipDecoder().decodeBytes(result.packedData);

        final newObj =
            BinaryReader(Uint8List.fromList(gZippedData)).readObject();

        final newRpcResult = RpcResult(reqMsgId: reqMsgId, result: newObj);
        _handleIncomingMessage(newRpcResult);
        return;
      }

      task?.complete(t.Result.ok(msg.result));
      _pending.remove(reqMsgId);
    } else if (msg is GzipPacked) {
      final gZippedData = GZipDecoder().decodeBytes(msg.packedData);
      final newObj = BinaryReader(Uint8List.fromList(gZippedData)).readObject();
      _handleIncomingMessage(newObj);
    }
  }

  Future<AuthorizationKey> connect() async {
    sender.add(obfuscation.preamble);
    await Future.delayed(Duration(milliseconds: 100));

    Future<AuthorizationKey> performKeyExchange() async {
      final uot = _UnEncryptedTransformer(
        receiver,
        obfuscation,
      );

      final dh = _DiffieHellman(sender, uot.stream, obfuscation, _idSeq);
      final ak = await dh.exchange();

      await uot.dispose();

      return ak;
    }

    final ak = authKey ??= await performKeyExchange();

    _trns = _EncryptedTransformer(receiver, ak, obfuscation);

    _trns.stream.listen((v) {
      _handleIncomingMessage(v);
    });

    return ak;
  }

  @override
  Future<t.Result<t.TlObject>> invoke(t.TlMethod method) async {
    final auth = authKey ??= await connect();

    final preferEncryption = auth.id != 0;

    final completer = Completer<t.Result>();
    final m = _idSeq.next(preferEncryption);

    // if (preferEncryption && _msgsToAck.isNotEmpty) {
    //   final ack = idSeq.next(false);
    //   final ackMsg = MsgsAck(msgIds: _msgsToAck.toList());
    //   _msgsToAck.clear();

    //   final container = MsgContainer(
    //     messages: [
    //       Msg(
    //         msgId: m.msgId,
    //         seqno: m.seqno,
    //         bytes: 0,
    //         body: msg,
    //       ),
    //       Msg(
    //         msgId: ack.msgId,
    //         seqno: ack.seqno,
    //         bytes: 0,
    //         body: ackMsg,
    //       )
    //     ],
    //   );

    //   return send(container, false);
    // }

    _pending[m.id] = completer;
    final buffer = auth.id == 0
        ? _encodeNoAuth(method, m)
        : _encodeWithAuth(method, m, sessionId, auth);

    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    sender.add(Uint8List.fromList(buffer));

    return completer.future;
  }
}
