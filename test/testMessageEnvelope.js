const bitcoinLib = require('bitcoinjs-lib');
const multihashing = require('multihashing');
const CID = require('cids');
const varint = require('varint');
const expect = require('chai').expect;
const ctnOffChainLib = require('../src/index');

describe('Create new Message Envelope', function () {
    it('should throw if no parameter is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope();
        }).to.throw(Error, 'Missing or invalid `msgInfo` parameter');
    });

    it('should throw if an invalid parameter is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope('bla');
        }).to.throw(Error, 'Missing or invalid `msgInfo` parameter');
    });

    it('should throw if an object missing property `msgType` is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
            });
        }).to.throw(Error, 'missing or invalid `msgType` property');
    });

    it('should throw if an object with an invalid `msgType` property is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: {}
            });
        }).to.throw(Error, 'missing or invalid `msgType` property');
    });

    it('should throw if an object missing property `msgOpts` is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
            });
        }).to.throw(Error, 'missing or invalid `msgOpts` property');
    });

    it('should throw if an object with an invalid `msgOpts` property (more than one byte) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0xffff
            });
        }).to.throw(Error, 'missing or invalid `msgOpts` property');
    });

    it('should throw if an object with an invalid `msgOpts` property (w/non-defined bits) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0xff
            });
        }).to.throw(Error, 'missing or invalid `msgOpts` property');
    });

    it('should throw if an object with an invalid `msgOpts` property (read confirmation for non send message) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
                msgOpts: 0x03
            });
        }).to.throw(Error, 'missing or invalid `msgOpts` property');
    });

    it('should throw if an object missing property `senderPubKeyHash`is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03
            });
        }).to.throw(Error, 'missing or invalid `senderPubKeyHash` property');
    });

    it('should throw if an object with an invalid `senderPubKeyHash` property (invalid base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: 'fjsk$*%&*@&%(*&@'
            });
        }).to.throw(Error, 'missing or invalid `senderPubKeyHash` property');
    });

    it('should throw if an object with an invalid `senderPubKeyHash` property (shorter base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.from('bla').toString('base64')
            });
        }).to.throw(Error, 'missing or invalid `senderPubKeyHash` property');
    });

    it('should throw if an object with an invalid `senderPubKeyHash` property (shorter Buffer) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.from('bla')
            });
        }).to.throw(Error, 'missing or invalid `senderPubKeyHash` property');
    });

    it('should throw if an object (w/send message) missing property `receiverPubKeyHash`is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.alloc(20, 0xff)
            });
        }).to.throw(Error, 'missing or invalid `receiverPubKeyHash` property');
    });

    it('should throw if an object (w/send message) with an invalid `receiverPubKeyHash` property (invalid base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.alloc(20, 0xff),
                receiverPubKeyHash: 'fjsk$*%&*@&%(*&@'
            });
        }).to.throw(Error, 'missing or invalid `receiverPubKeyHash` property');
    });

    it('should throw if an object (w/send message) with an invalid `receiverPubKeyHash` property (shorter base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.alloc(20, 0xff),
                receiverPubKeyHash: Buffer.from('bla').toString('base64')
            });
        }).to.throw(Error, 'missing or invalid `receiverPubKeyHash` property');
    });

    it('should throw if an object (w/send message) with an invalid `receiverPubKeyHash` property (shorter Buffer) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.alloc(20, 0xff),
                receiverPubKeyHash: Buffer.from('bla')
            });
        }).to.throw(Error, 'missing or invalid `receiverPubKeyHash` property');
    });

    it('should throw if an object with an invalid `timestamp` property is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.alloc(20, 0xff),
                receiverPubKeyHash: Buffer.alloc(20, 0xff),
                timestamp: 'bla'
            });
        }).to.throw(Error, 'invalid `timestamp` property');
    });

    it('should throw if an object missing property `stoProviderCode` is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.alloc(20, 0xff),
                receiverPubKeyHash: Buffer.alloc(20, 0xff),
                timestamp: new Date('2019-11-09').getTime()
            });
        }).to.throw(Error, 'missing or invalid `stoProviderCode` property');
    });

    it('should throw if an object with an invalid `stoProviderCode` property is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.alloc(20, 0xff),
                receiverPubKeyHash: Buffer.alloc(20, 0xff),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x00
            });
        }).to.throw(Error, 'missing or invalid `stoProviderCode` property');
    });

    it('should throw if an object missing property `msgRef` is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.alloc(20, 0xff),
                receiverPubKeyHash: Buffer.alloc(20, 0xff),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02
            });
        }).to.throw(Error, 'missing or invalid `msgRef` property');
    });

    it('should throw if an object with an invalid `msgRef` property (not a Buffer) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.alloc(20, 0xff),
                receiverPubKeyHash: Buffer.alloc(20, 0xff),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: 'bla'
            });
        }).to.throw(Error, 'missing or invalid `msgRef` property');
    });

    it('should throw if an object with an invalid `msgRef` property (not a valid CID) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: Buffer.alloc(20, 0xff),
                receiverPubKeyHash: Buffer.alloc(20, 0xff),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: Buffer.from('bla')
            });
        }).to.throw(Error, 'missing or invalid `msgRef` property');
    });

    it('should return a MessageEnvelope object', function () {
        const msgCid = new CID(0, 'dag-pb', multihashing(Buffer.from('This is only a test'),'sha2-256'));

        const msgEnv = new ctnOffChainLib.MessageEnvelope({
            msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
            msgOpts: 0x03,
            senderPubKeyHash: Buffer.alloc(20, 0xff),
            receiverPubKeyHash: Buffer.alloc(20, 0xff),
            timestamp: new Date('2019-11-09').getTime(),
            stoProviderCode: 0x02,
            msgRef: Buffer.from(msgCid.bytes)
        });

        expect(msgEnv).to.be.an.instanceof(ctnOffChainLib.MessageEnvelope);
    });

    it('should return a MessageEnvelope object if specifying log message with no receiver public key', function () {
        const msgCid = new CID(0, 'dag-pb', multihashing(Buffer.from('This is only a test'),'sha2-256'));

        const msgEnv = new ctnOffChainLib.MessageEnvelope({
            msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
            msgOpts: 0x01,
            senderPubKeyHash: Buffer.alloc(20, 0xff),
            timestamp: new Date('2019-11-09').getTime(),
            stoProviderCode: 0x02,
            msgRef: Buffer.from(msgCid.bytes)
        });

        expect(msgEnv).to.be.an.instanceof(ctnOffChainLib.MessageEnvelope);
    });

    it('should return a MessageEnvelope object even if no timestamp is passed', function () {
        const msgCid = new CID(0, 'dag-pb', multihashing(Buffer.from('This is only a test'),'sha2-256'));

        const msgEnv = new ctnOffChainLib.MessageEnvelope({
            msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
            msgOpts: 0x03,
            senderPubKeyHash: Buffer.alloc(20, 0xff),
            receiverPubKeyHash: Buffer.alloc(20, 0xff),
            timestamp: new Date('2019-11-09').getTime(),
            stoProviderCode: 0x02,
            msgRef: Buffer.from(msgCid.bytes)
        });

        expect(msgEnv).to.be.an.instanceof(ctnOffChainLib.MessageEnvelope);
    });
});

describe('Message Envelope instance', function () {
    const keyPair1 = bitcoinLib.ECPair.fromWIF('KySHu9Pe4eZmBQ8unFQGR1oNaYpUeXwmYux386mTioD1L72WYtYf');
    const keyPair2 = bitcoinLib.ECPair.fromWIF('L33Ty5rCmDg6Tzvi5D25aL7RCc2AV8ksN2Zq78wpKLpmznoqiSNs');
    const hashPubKey = keyPair => bitcoinLib.crypto.hash160(keyPair.publicKey);

    describe ('for send message with encryption and read confirmation', function () {
        const msgCid = new CID(0, 'dag-pb', multihashing(Buffer.from('This is only a test'),'sha2-256'));
        const msgEnv = new ctnOffChainLib.MessageEnvelope({
            msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
            msgOpts: 0x03,
            senderPubKeyHash: hashPubKey(keyPair1),
            receiverPubKeyHash: hashPubKey(keyPair2),
            timestamp: new Date('2019-11-09').getTime(),
            stoProviderCode: 0x02,
            msgRef: Buffer.from(msgCid.bytes)
        });
        const msgEnvHex = '584501010344e81b67da0be30136be2bc058232b721265c7fa4f7ec5b3b7840f2539cf6a878a736e13eaf378980000016e4d75dc00021220a4f8be35d524355a7cd5ffbff558bb76f81576dafa7fa5a976aaa3543f29b42a';

        it('should correctly report that message is encrypted', function () {
            expect(msgEnv.isMessageEncrypted).to.be.true;
        });

        it('should correctly report that sender expects a read confirmation', function () {
            expect(msgEnv.isMessageWithReadConfirmation).to.be.true;
        });

        it('should correctly report that it is not signed yet', function () {
            expect(msgEnv.isSigned).to.be.false;
        });

        it('should correctly indicate that signature cannot be verified', function () {
            expect(msgEnv.verifySignature()).to.be.undefined;
        });

        it('should return the correct hex string', function () {
            expect(msgEnv.hex).to.equal(msgEnvHex);
        });

        it('should return the correct base64 string', function () {
            expect(msgEnv.base64).to.equal(Buffer.from(msgEnvHex, 'hex').toString('base64'));
        });

        describe('signing', function () {
            const uncomprKeyPair = bitcoinLib.ECPair.makeRandom({compressed: false});
            const anyKeyPair = bitcoinLib.ECPair.makeRandom();

            it('should fail for uncompressed key pair', function () {
                expect(() => {
                    msgEnv.sign(uncomprKeyPair);
                }).to.throw(Error, 'Invalid public key format; it should be compressed');
            });

            it('should fail for incorrect key pair', function () {
                expect(() => {
                    msgEnv.sign(anyKeyPair);
                }).to.throw(Error, 'Passed in key pair does not match message sender\'s public key hash');
            });

            it('should work now', function () {
                expect(() => {
                    msgEnv.sign(keyPair1);
                }).not.to.throw();

                expect(msgEnv.isSigned).to.be.true;
                expect(msgEnv.verifySignature()).to.be.true;
            });

            it('should not fail if already signed', function () {
                expect(() => {
                    msgEnv.sign(keyPair1);
                }).not.to.throw();
            });

            it('should not verify signature if an error occurs', function () {
                // Simulate broken public key
                msgEnv.senderPubKey = msgEnv.senderPubKey.slice(0, msgEnv.senderPubKey.byteLength - 1);

                expect(msgEnv.verifySignature()).to.be.false;
            });

            it('should return the correct hex string afterwards', function () {
                const signMsgEnvHex = '584501010344e81b67da0be30136be2bc058232b721265c7fa4f7ec5b3b7840f2539cf6a878a736e13eaf378980000016e4d75dc00021220a4f8be35d524355a7cd5ffbff558bb76f81576dafa7fa5a976aaa3543f29b42a40ef8f25181c83f23ab43965cd9184d8906ff0dcbf86ae0583e5b22a475dc7c7c16698e9316cba3f2a1c78d2f17a8de8e68a9af8e7b8942ce76e7fb10ec2ef409d023fcff8acde07c6330a459da6332db3ea563ee353dadf0a955026ae2c08bd1992';

                expect(msgEnv.hex).to.equal(signMsgEnvHex);
            });

            it('should return the correct base64 string afterwards', function () {
                const signMsgEnvHex = '584501010344e81b67da0be30136be2bc058232b721265c7fa4f7ec5b3b7840f2539cf6a878a736e13eaf378980000016e4d75dc00021220a4f8be35d524355a7cd5ffbff558bb76f81576dafa7fa5a976aaa3543f29b42a40ef8f25181c83f23ab43965cd9184d8906ff0dcbf86ae0583e5b22a475dc7c7c16698e9316cba3f2a1c78d2f17a8de8e68a9af8e7b8942ce76e7fb10ec2ef409d023fcff8acde07c6330a459da6332db3ea563ee353dadf0a955026ae2c08bd1992';

                expect(msgEnv.base64).to.equal(Buffer.from(signMsgEnvHex, 'hex').toString('base64'));
            });
        });
    });

    describe ('for log message without encryption', function () {
        const msgCid = new CID(0, 'dag-pb', multihashing(Buffer.from('This is only a test'),'sha2-256'));
        const msgEnv = new ctnOffChainLib.MessageEnvelope({
            msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
            msgOpts: 0x00,
            senderPubKeyHash: hashPubKey(keyPair1),
            receiverPubKeyHash: hashPubKey(keyPair2),
            timestamp: new Date('2019-11-09').getTime(),
            stoProviderCode: 0x02,
            msgRef: Buffer.from(msgCid.bytes)
        });
        const msgEnvHex = '584501000044e81b67da0be30136be2bc058232b721265c7fa00000000000000000000000000000000000000000000016e4d75dc00021220a4f8be35d524355a7cd5ffbff558bb76f81576dafa7fa5a976aaa3543f29b42a';

        it('should correctly report that message is not encrypted', function () {
            expect(msgEnv.isMessageEncrypted).to.be.false;
        });

        it('should correctly report that sender does not expect a read confirmation', function () {
            expect(msgEnv.isMessageWithReadConfirmation).to.be.false;
        });

        it('should correctly report that it is not signed yet', function () {
            expect(msgEnv.isSigned).to.be.false;
        });

        it('should correctly indicate that signature cannot be verified', function () {
            expect(msgEnv.verifySignature()).to.be.undefined;
        });

        it('should return the correct hex string', function () {
            expect(msgEnv.hex).to.equal(msgEnvHex);
        });

        it('should return the correct base64 string', function () {
            expect(msgEnv.base64).to.equal(Buffer.from(msgEnvHex, 'hex').toString('base64'));
        });

        describe('signing', function () {
            const uncomprKeyPair = bitcoinLib.ECPair.makeRandom({compressed: false});
            const anyKeyPair = bitcoinLib.ECPair.makeRandom();

            it('should fail for uncompressed key pair', function () {
                expect(() => {
                    msgEnv.sign(uncomprKeyPair);
                }).to.throw(Error, 'Invalid public key format; it should be compressed');
            });

            it('should fail for incorrect key pair', function () {
                expect(() => {
                    msgEnv.sign(anyKeyPair);
                }).to.throw(Error, 'Passed in key pair does not match message sender\'s public key hash');
            });

            it('should work now', function () {
                expect(() => {
                    msgEnv.sign(keyPair1);
                }).not.to.throw();

                expect(msgEnv.isSigned).to.be.true;
                expect(msgEnv.verifySignature()).to.be.true;
            });

            it('should return the correct hex string afterwards', function () {
                const signMsgEnvHex = '584501000044e81b67da0be30136be2bc058232b721265c7fa00000000000000000000000000000000000000000000016e4d75dc00021220a4f8be35d524355a7cd5ffbff558bb76f81576dafa7fa5a976aaa3543f29b42a40aa4a03babe2fb5554c405bfaba868d6f00188c69cbe2418ae3c74558d0526f850635c1e1c60c5806a1c8b465accbe3ce3b90e03d21b32e65f3ff3ebfbb8ee330023fcff8acde07c6330a459da6332db3ea563ee353dadf0a955026ae2c08bd1992';

                expect(msgEnv.hex).to.equal(signMsgEnvHex);
            });

            it('should return the correct base64 string afterwards', function () {
                const signMsgEnvHex = '584501000044e81b67da0be30136be2bc058232b721265c7fa00000000000000000000000000000000000000000000016e4d75dc00021220a4f8be35d524355a7cd5ffbff558bb76f81576dafa7fa5a976aaa3543f29b42a40aa4a03babe2fb5554c405bfaba868d6f00188c69cbe2418ae3c74558d0526f850635c1e1c60c5806a1c8b465accbe3ce3b90e03d21b32e65f3ff3ebfbb8ee330023fcff8acde07c6330a459da6332db3ea563ee353dadf0a955026ae2c08bd1992';

                expect(msgEnv.base64).to.equal(Buffer.from(signMsgEnvHex, 'hex').toString('base64'));
            });
        });
    });
});

describe('Parse Message Envelope', function () {
    const keyPair1 = bitcoinLib.ECPair.fromWIF('KySHu9Pe4eZmBQ8unFQGR1oNaYpUeXwmYux386mTioD1L72WYtYf');
    const keyPair2 = bitcoinLib.ECPair.fromWIF('L33Ty5rCmDg6Tzvi5D25aL7RCc2AV8ksN2Zq78wpKLpmznoqiSNs');
    const hashPubKey = keyPair => bitcoinLib.crypto.hash160(keyPair.publicKey);
    const msgCid = new CID(0, 'dag-pb', multihashing(Buffer.from('This is only a test'),'sha2-256'));
    const msgEnv = new ctnOffChainLib.MessageEnvelope({
        msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
        msgOpts: 0x03,
        senderPubKeyHash: hashPubKey(keyPair1),
        receiverPubKeyHash: hashPubKey(keyPair2),
        timestamp: new Date('2019-11-09').getTime(),
        stoProviderCode: 0x02,
        msgRef: Buffer.from(msgCid.bytes)
    });
    const msgEnvBuf = msgEnv.buffer;
    const msgRefLength = msgEnvBuf.byteLength - 54;

    const signMsgEnv = new ctnOffChainLib.MessageEnvelope({
        msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
        msgOpts: 0x03,
        senderPubKeyHash: hashPubKey(keyPair1),
        receiverPubKeyHash: hashPubKey(keyPair2),
        timestamp: new Date('2019-11-09').getTime(),
        stoProviderCode: 0x02,
        msgRef: Buffer.from(msgCid.bytes)
    });
    signMsgEnv.sign(keyPair1);
    const signMsgEnvBuf = signMsgEnv.buffer;
    const signMsgRefLength = signMsgEnvBuf.byteLength - 54;

    it('should throw if incorrect parameter type is passed', function () {
        expect(() => {
            ctnOffChainLib.MessageEnvelope.fromBuffer(msgEnvBuf.toString('hex'));
        }).to.throw(TypeError, 'Invalid argument type; expected Buffer');
    });

    it('should throw if too short a Buffer is passed', function () {
        expect(() => {
            ctnOffChainLib.MessageEnvelope.fromBuffer(Buffer.alloc(56));
        }).to.throw(Error, 'Data buffer too short');
    });

    it('should throw if length prefix is invalid', function () {
        expect(() => {
            ctnOffChainLib.MessageEnvelope.fromBuffer(Buffer.alloc(57, 0x80));
        }).to.throw(Error, 'Invalid header length');
    });

    it('should throw if length prefix does not have the correct length', function () {
        expect(() => {
            ctnOffChainLib.MessageEnvelope.fromBuffer(msgEnvBuf.slice(0, msgEnvBuf.byteLength - 1));
        }).to.throw(Error, 'Inconsistent header length');
    });

    it('should throw if structure ID byte is invalid', function () {
        const badMsgEnvBuf = Buffer.concat([msgEnvBuf]);
        badMsgEnvBuf[1] = 'X'.charCodeAt();

        expect(() => {
            ctnOffChainLib.MessageEnvelope.fromBuffer(badMsgEnvBuf);
        }).to.throw(Error, 'invalid structure ID');
    });

    it('should throw if version byte is invalid', function () {
        const badMsgEnvBuf = Buffer.concat([msgEnvBuf]);
        badMsgEnvBuf[2] = 0xff;

        expect(() => {
            ctnOffChainLib.MessageEnvelope.fromBuffer(badMsgEnvBuf);
        }).to.throw(Error, 'invalid version byte');
    });

    it('should throw if message type byte is invalid', function () {
        const badMsgEnvBuf = Buffer.concat([msgEnvBuf]);
        badMsgEnvBuf[3] = 0xff;

        expect(() => {
            ctnOffChainLib.MessageEnvelope.fromBuffer(badMsgEnvBuf);
        }).to.throw(Error, 'invalid message type');
    });

    it('should throw if timestamp bytes have an invalid value', function () {
        const badMsgEnvBuf = Buffer.concat([msgEnvBuf]);
        ctnOffChainLib.Util.writeInt64BE(Number.MAX_SAFE_INTEGER, badMsgEnvBuf, 45);

        expect(() => {
            ctnOffChainLib.MessageEnvelope.fromBuffer(badMsgEnvBuf);
        }).to.throw(Error, 'invalid timestamp');
    });

    it('should throw if storage provider code byte is invalid', function () {
        const badMsgEnvBuf = Buffer.concat([msgEnvBuf]);
        badMsgEnvBuf.writeUInt8(0xff, 53);

        expect(() => {
            ctnOffChainLib.MessageEnvelope.fromBuffer(badMsgEnvBuf);
        }).to.throw(Error, 'invalid storage provider code');
    });

    it('should throw if message reference bytes have an invalid value', function () {
        const badMsgEnvBuf = Buffer.concat([msgEnvBuf]);
        badMsgEnvBuf.fill(0xff, 54, 54 + msgRefLength);

        expect(() => {
            ctnOffChainLib.MessageEnvelope.fromBuffer(badMsgEnvBuf);
        }).to.throw(Error, 'invalid message reference');
    });

    it('should return an object that matches original one', function () {
        const msgEnv2 = ctnOffChainLib.MessageEnvelope.fromBuffer(msgEnvBuf);

        expect(msgEnv2.hex).to.equals(msgEnv.hex);
    });

    describe('from hex', function () {
        it('should return an object that matches original one', function () {
            const msgEnv2 = ctnOffChainLib.MessageEnvelope.fromHex(msgEnvBuf.toString('hex'));

            expect(msgEnv2.hex).to.equals(msgEnv.hex);
        });
    });

    describe('from base64', function () {
        it('should return an object that matches original one', function () {
            const msgEnv2 = ctnOffChainLib.MessageEnvelope.fromBase64(msgEnvBuf.toString('base64'));

            expect(msgEnv2.base64).to.equals(msgEnv.base64);
        });
    });

    describe('for log message', function () {
        const logMsgEnv = new ctnOffChainLib.MessageEnvelope({
            msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
            msgOpts: 0x01,
            senderPubKeyHash: hashPubKey(keyPair1),
            timestamp: new Date('2019-11-09').getTime(),
            stoProviderCode: 0x02,
            msgRef: Buffer.from(msgCid.bytes)
        });

        it('should return an object that matches original one', function () {
            const logMsgEnv2 = ctnOffChainLib.MessageEnvelope.fromBuffer(logMsgEnv.buffer);

            expect(logMsgEnv2.hex).to.equals(logMsgEnv.hex);
        });
    });

    describe('that is signed', function () {
        const uncomprKeyPair = bitcoinLib.ECPair.makeRandom({compressed: false});
        const anyKeyPair = bitcoinLib.ECPair.makeRandom();

        it('should throw if signature is too short', function () {
            const badSignMsgEnvBuf = Buffer.concat([signMsgEnvBuf]).slice(0, msgEnvBuf.byteLength + 33);

            expect(() => {
                ctnOffChainLib.MessageEnvelope.fromBuffer(badSignMsgEnvBuf);
            }).to.throw(Error, 'Signature data too short');
        });

        it('should throw if signature length is invalid', function () {
            const badSignMsgEnvBuf = Buffer.concat([signMsgEnvBuf]);
            const badSign = badSignMsgEnvBuf.slice(msgEnvBuf.byteLength);
            badSign.fill(0xff, 0);

            expect(() => {
                ctnOffChainLib.MessageEnvelope.fromBuffer(badSignMsgEnvBuf);
            }).to.throw(Error, 'Invalid signature length');
        });

        it('should throw if signature length too small', function () {
            const badSignMsgEnvBuf = Buffer.concat([signMsgEnvBuf]);
            const badSign = badSignMsgEnvBuf.slice(msgEnvBuf.byteLength);
            badSign.writeUInt8(0x00, 0);

            expect(() => {
                ctnOffChainLib.MessageEnvelope.fromBuffer(badSignMsgEnvBuf);
            }).to.throw(Error, 'Inconsistent signature length');
        });

        it('should throw if signature shorter than recorded length', function () {
            const badSignMsgEnvBuf = Buffer.concat([signMsgEnvBuf]);
            const badSign = badSignMsgEnvBuf.slice(msgEnvBuf.byteLength);
            Buffer.from(varint.encode(badSign.byteLength)).copy(badSign);

            expect(() => {
                ctnOffChainLib.MessageEnvelope.fromBuffer(badSignMsgEnvBuf);
            }).to.throw(Error, 'Inconsistent signature data: signature shorter than expected');
        });

        it('should throw if public key is missing', function () {
            let badSignMsgEnvBuf = Buffer.concat([signMsgEnvBuf]);
            const badSign = badSignMsgEnvBuf.slice(msgEnvBuf.byteLength);
            const badSignLength = varint.decode(badSign);
            badSignMsgEnvBuf = badSignMsgEnvBuf.slice(0, msgEnvBuf.byteLength + 1 + badSignLength);

            expect(() => {
                ctnOffChainLib.MessageEnvelope.fromBuffer(badSignMsgEnvBuf);
            }).to.throw(Error, 'Inconsistent signature data: missing public key');
        });

        it('should throw if public key is invalid', function () {
            let badSignMsgEnvBuf = Buffer.concat([signMsgEnvBuf]);
            badSignMsgEnvBuf = badSignMsgEnvBuf.slice(0, badSignMsgEnvBuf.byteLength - 1);

            expect(() => {
                ctnOffChainLib.MessageEnvelope.fromBuffer(badSignMsgEnvBuf);
            }).to.throw(Error, 'Inconsistent signature data: invalid public key');
        });

        it('should throw if public key is not compressed', function () {
            let badSignMsgEnvBuf = Buffer.concat([signMsgEnvBuf]);
            const badSign = badSignMsgEnvBuf.slice(msgEnvBuf.byteLength);
            const badSignLength = varint.decode(badSign);
            badSignMsgEnvBuf = badSignMsgEnvBuf.slice(0, msgEnvBuf.byteLength + 1 + badSignLength);
            badSignMsgEnvBuf = Buffer.concat([badSignMsgEnvBuf, uncomprKeyPair.publicKey]);

            expect(() => {
                ctnOffChainLib.MessageEnvelope.fromBuffer(badSignMsgEnvBuf);
            }).to.throw(Error, 'Inconsistent signature data: invalid public key format; it should be compressed');
        });

        it('should throw if public key is not correct', function () {
            let badSignMsgEnvBuf = Buffer.concat([signMsgEnvBuf]);
            const badSign = badSignMsgEnvBuf.slice(msgEnvBuf.byteLength);
            const badSignLength = varint.decode(badSign);
            badSignMsgEnvBuf = badSignMsgEnvBuf.slice(0, msgEnvBuf.byteLength + 1 + badSignLength);
            badSignMsgEnvBuf = Buffer.concat([badSignMsgEnvBuf, anyKeyPair.publicKey]);

            expect(() => {
                ctnOffChainLib.MessageEnvelope.fromBuffer(badSignMsgEnvBuf);
            }).to.throw(Error, 'Inconsistent signature data: public key does not match message sender\'s public key hash');
        });

        it('should return an object that matches original one', function () {
            const signMsgEnv2 = ctnOffChainLib.MessageEnvelope.fromBuffer(signMsgEnvBuf);

            expect(signMsgEnv2.hex).to.equals(signMsgEnv.hex);
        });
    });
});
