const bitcoinLib = require('bitcoinjs-lib');
const multihashing = require('multihashing');
const CID = require('cids');
const varint = require('varint');
const expect = require('chai').expect;
const ctnOffChainLib = require('../src/index');

describe('Create new Message Receipt', function () {
    const keyPair1 = bitcoinLib.ECPair.fromWIF('KySHu9Pe4eZmBQ8unFQGR1oNaYpUeXwmYux386mTioD1L72WYtYf');
    const keyPair2 = bitcoinLib.ECPair.fromWIF('L33Ty5rCmDg6Tzvi5D25aL7RCc2AV8ksN2Zq78wpKLpmznoqiSNs');
    const hashPubKey = keyPair => bitcoinLib.crypto.hash160(keyPair.publicKey);
    const msgCid = new CID(0, 'dag-pb', multihashing(Buffer.from('This is only a test'),'sha2-256'));
    const sendMsgEnv = new ctnOffChainLib.MessageEnvelope({
        msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
        msgOpts: 0x03,
        senderPubKeyHash: hashPubKey(keyPair1),
        receiverPubKeyHash: hashPubKey(keyPair2),
        timestamp: new Date('2019-11-09').getTime(),
        stoProviderCode: 0x02,
        msgRef: msgCid.buffer
    });
    const msgEnvCid = new CID(0, 'dag-pb', multihashing(sendMsgEnv.buffer,'sha2-256'));
    const logMsgEnv = new ctnOffChainLib.MessageEnvelope({
        msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
        msgOpts: 0x01,
        senderPubKeyHash: hashPubKey(keyPair1),
        timestamp: new Date('2019-11-09').getTime(),
        stoProviderCode: 0x02,
        msgRef: msgCid.buffer
    });

    it('should throw if no parameter is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt();
        }).to.throw(Error, 'Missing or invalid `rcptInfo` parameter');
    });

    it('should throw if an invalid parameter is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt('bla');
        }).to.throw(Error, 'Missing or invalid `rcptInfo` parameter');
    });

    it('should throw if an object missing property `msgInfo` is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
            });
        }).to.throw(Error, 'missing or invalid `msgInfo` property');
    });

    it('should throw if an object with an invalid `msgInfo` property is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: 'bla'
            });
        }).to.throw(Error, 'missing or invalid `msgInfo` property');
    });

    it('should throw if a log message envelope is passed in property `msgInfo`', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: logMsgEnv
            });
        }).to.throw(Error, 'inconsistent `msgInfo` property: message does not require receipt');
    });

    it('should throw if an object missing property `msgInfo.senderPubKeyHash`is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {}
            });
        }).to.throw(Error, 'missing or invalid `msgInfo.senderPubKeyHash` property');
    });

    it('should throw if an object with an invalid `msgInfo.senderPubKeyHash` property (invalid base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {
                    senderPubKeyHash: 'fjsk$*%&*@&%(*&@'
                }
            });
        }).to.throw(Error, 'missing or invalid `msgInfo.senderPubKeyHash` property');
    });

    it('should throw if an object with an invalid `msgInfo.senderPubKeyHash` property (shorter base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {
                    senderPubKeyHash: Buffer.from('bla').toString('base64')
                }
            });
        }).to.throw(Error, 'missing or invalid `msgInfo.senderPubKeyHash` property');
    });

    it('should throw if an object with an invalid `msgInfo.senderPubKeyHash` property (shorter Buffer) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {
                    senderPubKeyHash: Buffer.from('bla')
                }
            });
        }).to.throw(Error, 'missing or invalid `msgInfo.senderPubKeyHash` property');
    });

    it('should throw if an object missing property `msgInfo.receiverPubKeyHash`is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff)
                }
            });
        }).to.throw(Error, 'missing or invalid `msgInfo.receiverPubKeyHash` property');
    });

    it('should throw if an object with an invalid `msgInfo.receiverPubKeyHash` property (invalid base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: 'fjsk$*%&*@&%(*&@'
                }
            });
        }).to.throw(Error, 'missing or invalid `msgInfo.receiverPubKeyHash` property');
    });

    it('should throw if an object with an invalid `msgInfo.receiverPubKeyHash` property (shorter base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: Buffer.from('bla').toString('base64')
                }
            });
        }).to.throw(Error, 'missing or invalid `msgInfo.receiverPubKeyHash` property');
    });

    it('should throw if an object with an invalid `msgInfo.receiverPubKeyHash` property (shorter Buffer) is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: Buffer.from('bla')
                }
            });
        }).to.throw(Error, 'missing or invalid `msgInfo.receiverPubKeyHash` property');
    });

    it('should throw if an object with an invalid `timestamp` property is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: Buffer.alloc(20, 0xff)
                },
                timestamp: 'bla'
            });
        }).to.throw(Error, 'invalid `timestamp` property');
    });

    it('should throw if an object missing property `msgEnvCid` is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: Buffer.alloc(20, 0xff)
                },
                timestamp: new Date('2019-11-09').getTime()
            });
        }).to.throw(Error, 'missing or invalid `msgEnvCid` property');
    });

    it('should throw if an object with an invalid `msgEnvCid` property is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: Buffer.alloc(20, 0xff)
                },
                timestamp: new Date('2019-11-09').getTime(),
                msgEnvCid: Buffer.from('bla')
            });
        }).to.throw(Error, 'missing or invalid `msgEnvCid` property');
    });

    it('should throw if an object with an inconsistent value in property `msgEnvCid` is passed', function () {
        expect(() => {
            new ctnOffChainLib.MessageReceipt({
                msgInfo: sendMsgEnv,
                timestamp: new Date('2019-11-09').getTime(),
                msgEnvCid: msgCid
            });
        }).to.throw(Error, 'inconsistent `msgEnvCid` property: it does not match message envelope');
    });

    it('should return a MessageReceipt object', function () {
        const msgRcpt = new ctnOffChainLib.MessageReceipt({
            msgInfo: sendMsgEnv,
            timestamp: new Date('2019-11-09').getTime(),
            msgEnvCid: msgEnvCid
        });

        expect(msgRcpt).to.be.an.instanceof(ctnOffChainLib.MessageReceipt);
    });

    it('should return a MessageReceipt object even if no timestamp is passed', function () {
        const msgRcpt = new ctnOffChainLib.MessageReceipt({
            msgInfo: sendMsgEnv,
            msgEnvCid: msgEnvCid
        });

        expect(msgRcpt).to.be.an.instanceof(ctnOffChainLib.MessageReceipt);
    });
});

describe('Message Receipt instance', function () {
    const keyPair1 = bitcoinLib.ECPair.fromWIF('KySHu9Pe4eZmBQ8unFQGR1oNaYpUeXwmYux386mTioD1L72WYtYf');
    const keyPair2 = bitcoinLib.ECPair.fromWIF('L33Ty5rCmDg6Tzvi5D25aL7RCc2AV8ksN2Zq78wpKLpmznoqiSNs');
    const hashPubKey = keyPair => bitcoinLib.crypto.hash160(keyPair.publicKey);
    const msgCid = new CID(0, 'dag-pb', multihashing(Buffer.from('This is only a test'),'sha2-256'));
    const sendMsgEnv = new ctnOffChainLib.MessageEnvelope({
        msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
        msgOpts: 0x03,
        senderPubKeyHash: hashPubKey(keyPair1),
        receiverPubKeyHash: hashPubKey(keyPair2),
        timestamp: new Date('2019-11-09').getTime(),
        stoProviderCode: 0x02,
        msgRef: msgCid.buffer
    });
    const msgEnvCid = new CID(0, 'dag-pb', multihashing(sendMsgEnv.buffer,'sha2-256'));

    describe('not passing message envelope', function () {
        const msgRcpt = new ctnOffChainLib.MessageReceipt({
            msgInfo: {
                senderPubKeyHash: sendMsgEnv.senderPubKeyHash,
                receiverPubKeyHash: sendMsgEnv.receiverPubKeyHash
            },
            timestamp: new Date('2019-11-09').getTime(),
            msgEnvCid: msgEnvCid
        });
        const msgRcptHex = '55520144e81b67da0be30136be2bc058232b721265c7fa4f7ec5b3b7840f2539cf6a878a736e13eaf378980000016e4d75dc0012205974ca7b881b524eaffab90cdc533a43e2c1e3cc9ffbbb8c87f722f03c57744c';

        it('should correctly report that message is not checked', function () {
            expect(msgRcpt.isMessageChecked()).to.be.false;
        });

        it('should correctly report that it is not signed yet', function () {
            expect(msgRcpt.isSigned()).to.be.false;
        });

        it('should correctly indicate that signature cannot be verified', function () {
            expect(msgRcpt.verifySignature()).to.be.undefined;
        });

        it('should return the correct hex string', function () {
            expect(msgRcpt.hex).to.equal(msgRcptHex);
        });

        describe('checking message', function () {
            const logMsgEnv = new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
                msgOpts: 0x01,
                senderPubKeyHash: hashPubKey(keyPair1),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: msgCid.buffer
            });
            const noReadConfSendMsgEnv = new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x01,
                senderPubKeyHash: hashPubKey(keyPair1),
                receiverPubKeyHash: hashPubKey(keyPair2),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: msgCid.buffer
            });
            const keyPair3 = bitcoinLib.ECPair.makeRandom();
            const keyPair4 = bitcoinLib.ECPair.makeRandom();
            const sendMsgEnv2 = new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: hashPubKey(keyPair3),
                receiverPubKeyHash: hashPubKey(keyPair2),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: msgCid.buffer
            });
            const sendMsgEnv3 = new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: hashPubKey(keyPair1),
                receiverPubKeyHash: hashPubKey(keyPair4),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: msgCid.buffer
            });
            const msg2Cid = new CID(0, 'dag-pb', multihashing(Buffer.from('Another test message'),'sha2-256'));
            const sendMsgEnv4 = new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: hashPubKey(keyPair1),
                receiverPubKeyHash: hashPubKey(keyPair2),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: msg2Cid.buffer
            });

            it('should fail if anything other than a message envelope is passed', function () {
                expect(msgRcpt.checkMessage('bla')).to.be.false;
                expect(msgRcpt.checkMessageError).to.equal('Invalid message: not an instance of MessageEnvelope');
            });

            it('should fail if a message envelope not for a send message is passed', function () {
                expect(msgRcpt.checkMessage(logMsgEnv)).to.be.false;
                expect(msgRcpt.checkMessageError).to.equal('Invalid message: it does not require receipt');
            });

            it('should fail if a message envelope for a send message with no read confirmation is passed', function () {
                expect(msgRcpt.checkMessage(noReadConfSendMsgEnv)).to.be.false;
                expect(msgRcpt.checkMessageError).to.equal('Invalid message: it does not require receipt');
            });

            it('should fail if a message envelope with a different sender public key hash is passed', function () {
                expect(msgRcpt.checkMessage(sendMsgEnv2)).to.be.false;
                expect(msgRcpt.checkMessageError).to.equal('Invalid message: it does not match sender and/or receiver');
            });

            it('should fail if a message envelope with a different receiver public key hash is passed', function () {
                expect(msgRcpt.checkMessage(sendMsgEnv3)).to.be.false;
                expect(msgRcpt.checkMessageError).to.equal('Invalid message: it does not match sender and/or receiver');
            });

            it('should fail if a message envelope for a different message is passed', function () {
                expect(msgRcpt.checkMessage(sendMsgEnv4)).to.be.false;
                expect(msgRcpt.checkMessageError).to.equal('Invalid message: it does not match message envelope CID');
            });

            it('should work now', function () {
                expect(msgRcpt.checkMessage(sendMsgEnv)).to.be.true;
                expect(msgRcpt.isMessageChecked()).to.be.true;
            });

            it('should fail if message was already checked', function () {
                expect(msgRcpt.checkMessage(sendMsgEnv)).to.be.false;
                expect(msgRcpt.checkMessageError).to.equal('Message already checked for receipt');
            });
        });

        describe('signing', function () {
            const uncomprKeyPair = bitcoinLib.ECPair.makeRandom({compressed: false});
            const anyKeyPair = bitcoinLib.ECPair.makeRandom();

            it('should fail for uncompressed key pair', function () {
                expect(() => {
                    msgRcpt.sign(uncomprKeyPair);
                }).to.throw(Error, 'Invalid public key format; it should be compressed');
            });

            it('should fail for incorrect key pair', function () {
                expect(() => {
                    msgRcpt.sign(anyKeyPair);
                }).to.throw(Error, 'Passed in key pair does not match message receiver\'s public key hash');
            });

            it('should work now', function () {
                expect(() => {
                    msgRcpt.sign(keyPair2);
                }).not.to.throw();

                expect(msgRcpt.isSigned()).to.be.true;
                expect(msgRcpt.verifySignature()).to.be.true;
            });

            it('should not fail if already signed', function () {
                expect(() => {
                    msgRcpt.sign(keyPair2);
                }).not.to.throw();
            });

            it('should not verify signature if an error occurs', function () {
                // Simulate broken public key
                msgRcpt.receiverPubKey = msgRcpt.receiverPubKey.slice(0, msgRcpt.receiverPubKey.byteLength - 1);

                expect(msgRcpt.verifySignature()).to.be.false;
            });

            it('should return the correct hex string afterwards', function () {
                const signMsgRcptHex = '55520144e81b67da0be30136be2bc058232b721265c7fa4f7ec5b3b7840f2539cf6a878a736e13eaf378980000016e4d75dc0012205974ca7b881b524eaffab90cdc533a43e2c1e3cc9ffbbb8c87f722f03c57744c4099f2111a941686ea8e317a6aff53d795719da4892538b7d250bd8226d0949f3723eb84e11998312ffb4795b70fb92a77e1a617e2dd1af4ae7f308ee40a0f7c97035eb7909703f997c823314d367d818e93224b8f5f26a3c22ae7181db0076d101e';

                expect(msgRcpt.hex).to.equal(signMsgRcptHex);
            });
        });
    });

    describe('passing message envelope', function () {
        const msgRcpt = new ctnOffChainLib.MessageReceipt({
            msgInfo: sendMsgEnv,
            timestamp: new Date('2019-11-09').getTime(),
            msgEnvCid: msgEnvCid
        });
        const msgRcptHex = '55520144e81b67da0be30136be2bc058232b721265c7fa4f7ec5b3b7840f2539cf6a878a736e13eaf378980000016e4d75dc0012205974ca7b881b524eaffab90cdc533a43e2c1e3cc9ffbbb8c87f722f03c57744c';

        it('should correctly report that message is checked', function () {
            expect(msgRcpt.isMessageChecked()).to.be.true;
        });

        it('should correctly report that it is not signed yet', function () {
            expect(msgRcpt.isSigned()).to.be.false;
        });

        it('should correctly indicate that signature cannot be verified', function () {
            expect(msgRcpt.verifySignature()).to.be.undefined;
        });

        it('should return the correct hex string', function () {
            expect(msgRcpt.hex).to.equal(msgRcptHex);
        });
    });
});

describe('Parse Message Receipt', function () {
    const keyPair1 = bitcoinLib.ECPair.fromWIF('KySHu9Pe4eZmBQ8unFQGR1oNaYpUeXwmYux386mTioD1L72WYtYf');
    const keyPair2 = bitcoinLib.ECPair.fromWIF('L33Ty5rCmDg6Tzvi5D25aL7RCc2AV8ksN2Zq78wpKLpmznoqiSNs');
    const hashPubKey = keyPair => bitcoinLib.crypto.hash160(keyPair.publicKey);
    const msgCid = new CID(0, 'dag-pb', multihashing(Buffer.from('This is only a test'),'sha2-256'));
    const sendMsgEnv = new ctnOffChainLib.MessageEnvelope({
        msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
        msgOpts: 0x03,
        senderPubKeyHash: hashPubKey(keyPair1),
        receiverPubKeyHash: hashPubKey(keyPair2),
        timestamp: new Date('2019-11-09').getTime(),
        stoProviderCode: 0x02,
        msgRef: msgCid.buffer
    });
    const msgEnvCid = new CID(0, 'dag-pb', multihashing(sendMsgEnv.buffer,'sha2-256'));

    const msgRcpt = new ctnOffChainLib.MessageReceipt({
        msgInfo: sendMsgEnv,
        timestamp: new Date('2019-11-09').getTime(),
        msgEnvCid: msgEnvCid
    });
    const msgRcptBuf = msgRcpt.buffer;
    const msgEnvCidLength = msgRcptBuf.byteLength - 51;

    const signMsgRcpt = new ctnOffChainLib.MessageReceipt({
        msgInfo: sendMsgEnv,
        timestamp: new Date('2019-11-09').getTime(),
        msgEnvCid: msgEnvCid
    });
    signMsgRcpt.sign(keyPair2);
    const signMsgRcptBuf = signMsgRcpt.buffer;
    const signMsgEnvCidLength = signMsgRcptBuf.byteLength - 51;

    it('should throw if incorrect parameter type is passed', function () {
        expect(() => {
            ctnOffChainLib.MessageReceipt.fromBuffer(msgRcptBuf.toString('hex'));
        }).to.throw(TypeError, 'Invalid argument type; expected Buffer');
    });

    it('should throw if too short a Buffer is passed', function () {
        expect(() => {
            ctnOffChainLib.MessageReceipt.fromBuffer(Buffer.alloc(53));
        }).to.throw(Error, 'Data buffer too short');
    });

    it('should throw if length prefix is invalid', function () {
        expect(() => {
            ctnOffChainLib.MessageReceipt.fromBuffer(Buffer.alloc(54, 0x80));
        }).to.throw(Error, 'Invalid header length');
    });

    it('should throw if length prefix does not have the correct length', function () {
        expect(() => {
            ctnOffChainLib.MessageReceipt.fromBuffer(msgRcptBuf.slice(0, msgRcptBuf.byteLength - 1));
        }).to.throw(Error, 'Inconsistent header length');
    });

    it('should throw if structure ID byte is invalid', function () {
        const badMsgRcptBuf = Buffer.concat([msgRcptBuf]);
        badMsgRcptBuf[1] = 'X'.charCodeAt();

        expect(() => {
            ctnOffChainLib.MessageReceipt.fromBuffer(badMsgRcptBuf);
        }).to.throw(Error, 'invalid structure ID');
    });

    it('should throw if version byte is invalid', function () {
        const badMsgRcptBuf = Buffer.concat([msgRcptBuf]);
        badMsgRcptBuf[2] = 0xff;

        expect(() => {
            ctnOffChainLib.MessageReceipt.fromBuffer(badMsgRcptBuf);
        }).to.throw(Error, 'invalid version byte');
    });

    it('should throw if timestamp bytes have an invalid value', function () {
        const badMsgRcptBuf = Buffer.concat([msgRcptBuf]);
        ctnOffChainLib.Util.writeInt64BE(Number.MAX_SAFE_INTEGER, badMsgRcptBuf, 43);

        expect(() => {
            ctnOffChainLib.MessageReceipt.fromBuffer(badMsgRcptBuf);
        }).to.throw(Error, 'invalid timestamp');
    });

    it('should throw if message envelope CID bytes have an invalid value', function () {
        const badMsgRcptBuf = Buffer.concat([msgRcptBuf]);
        badMsgRcptBuf.fill(0xff, 51, 51 + msgEnvCidLength);

        expect(() => {
            ctnOffChainLib.MessageReceipt.fromBuffer(badMsgRcptBuf);
        }).to.throw(Error, 'invalid message content CID');
    });

    it('should return an object that matches original one', function () {
        const msgRcpt2 = ctnOffChainLib.MessageReceipt.fromBuffer(msgRcptBuf);

        expect(msgRcpt2.hex).to.equals(msgRcpt.hex);
    });

    describe('from hex', function () {
        it('should return an object that matches original one', function () {
            const msgRcpt2 = ctnOffChainLib.MessageReceipt.fromHex(msgRcptBuf.toString('hex'));

            expect(msgRcpt2.hex).to.equals(msgRcpt.hex);
        });
    });

    describe('that is signed', function () {
        const uncomprKeyPair = bitcoinLib.ECPair.makeRandom({compressed: false});
        const anyKeyPair = bitcoinLib.ECPair.makeRandom();

        it('should throw if signature is too short', function () {
            const badSignMsgRcptBuf = Buffer.concat([signMsgRcptBuf]).slice(0, msgRcptBuf.byteLength + 33);

            expect(() => {
                ctnOffChainLib.MessageReceipt.fromBuffer(badSignMsgRcptBuf);
            }).to.throw(Error, 'Signature data too short');
        });

        it('should throw if signature length is invalid', function () {
            const badSignMsgRcptBuf = Buffer.concat([signMsgRcptBuf]);
            const badSign = badSignMsgRcptBuf.slice(msgRcptBuf.byteLength);
            badSign.fill(0xff, 0);

            expect(() => {
                ctnOffChainLib.MessageReceipt.fromBuffer(badSignMsgRcptBuf);
            }).to.throw(Error, 'Invalid signature length');
        });

        it('should throw if signature length too small', function () {
            const badSignMsgRcptBuf = Buffer.concat([signMsgRcptBuf]);
            const badSign = badSignMsgRcptBuf.slice(msgRcptBuf.byteLength);
            badSign.writeUInt8(0x00, 0);

            expect(() => {
                ctnOffChainLib.MessageReceipt.fromBuffer(badSignMsgRcptBuf);
            }).to.throw(Error, 'Inconsistent signature length');
        });

        it('should throw if signature shorter than recorded length', function () {
            const badSignMsgRcptBuf = Buffer.concat([signMsgRcptBuf]);
            const badSign = badSignMsgRcptBuf.slice(msgRcptBuf.byteLength);
            Buffer.from(varint.encode(badSign.byteLength)).copy(badSign);

            expect(() => {
                ctnOffChainLib.MessageReceipt.fromBuffer(badSignMsgRcptBuf);
            }).to.throw(Error, 'Inconsistent signature data: signature shorter than expected');
        });

        it('should throw if public key is missing', function () {
            let badSignMsgRcptBuf = Buffer.concat([signMsgRcptBuf]);
            const badSign = badSignMsgRcptBuf.slice(msgRcptBuf.byteLength);
            const badSignLength = varint.decode(badSign);
            badSignMsgRcptBuf = badSignMsgRcptBuf.slice(0, msgRcptBuf.byteLength + 1 + badSignLength);

            expect(() => {
                ctnOffChainLib.MessageReceipt.fromBuffer(badSignMsgRcptBuf);
            }).to.throw(Error, 'Inconsistent signature data: missing public key');
        });

        it('should throw if public key is invalid', function () {
            let badSignMsgRcptBuf = Buffer.concat([signMsgRcptBuf]);
            badSignMsgRcptBuf = badSignMsgRcptBuf.slice(0, badSignMsgRcptBuf.byteLength - 1);

            expect(() => {
                ctnOffChainLib.MessageReceipt.fromBuffer(badSignMsgRcptBuf);
            }).to.throw(Error, 'Inconsistent signature data: invalid public key');
        });

        it('should throw if public key is not compressed', function () {
            let badSignMsgRcptBuf = Buffer.concat([signMsgRcptBuf]);
            const badSign = badSignMsgRcptBuf.slice(msgRcptBuf.byteLength);
            const badSignLength = varint.decode(badSign);
            badSignMsgRcptBuf = badSignMsgRcptBuf.slice(0, msgRcptBuf.byteLength + 1 + badSignLength);
            badSignMsgRcptBuf = Buffer.concat([badSignMsgRcptBuf, uncomprKeyPair.publicKey]);

            expect(() => {
                ctnOffChainLib.MessageReceipt.fromBuffer(badSignMsgRcptBuf);
            }).to.throw(Error, 'Inconsistent signature data: invalid public key format; it should be compressed');
        });

        it('should throw if public key is not correct', function () {
            let badSignMsgRcptBuf = Buffer.concat([signMsgRcptBuf]);
            const badSign = badSignMsgRcptBuf.slice(msgRcptBuf.byteLength);
            const badSignLength = varint.decode(badSign);
            badSignMsgRcptBuf = badSignMsgRcptBuf.slice(0, msgRcptBuf.byteLength + 1 + badSignLength);
            badSignMsgRcptBuf = Buffer.concat([badSignMsgRcptBuf, anyKeyPair.publicKey]);

            expect(() => {
                ctnOffChainLib.MessageReceipt.fromBuffer(badSignMsgRcptBuf);
            }).to.throw(Error, 'Inconsistent signature data: public key does not match message receiver\'s public key hash');
        });

        it('should return an object that matches original one', function () {
            const signMsgRcpt2 = ctnOffChainLib.MessageReceipt.fromBuffer(signMsgRcptBuf);

            expect(signMsgRcpt2.hex).to.equals(signMsgRcpt.hex);
        });
    });
});
