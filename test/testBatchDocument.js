const zlib = require('zlib');
const bitcoinLib = require('bitcoinjs-lib');
const multihashing = require('multihashing');
const CID = require('cids');
const varint = require('varint');
const expect = require('chai').expect;
const ctnOffChainLib = require('../src/index');

describe('Create new Batch Document', function () {
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
    const sendMsgEnvCid = new CID(0, 'dag-pb', multihashing(sendMsgEnv.buffer,'sha2-256'));
    const logMsgEnv = new ctnOffChainLib.MessageEnvelope({
        msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
        msgOpts: 0x01,
        senderPubKeyHash: hashPubKey(keyPair1),
        timestamp: new Date('2019-11-09').getTime(),
        stoProviderCode: 0x02,
        msgRef: msgCid.buffer
    });
    const logMsgEnvCid = new CID(0, 'dag-pb', multihashing(logMsgEnv.buffer,'sha2-256'));
    const sendMsgRcpt = new ctnOffChainLib.MessageReceipt({
        msgInfo: sendMsgEnv,
        timestamp: new Date('2019-11-09').getTime(),
        msgEnvCid: sendMsgEnvCid
    });
    const sendMsgRcptCid = new CID(0, 'dag-pb', multihashing(sendMsgRcpt.buffer,'sha2-256'));

    it('should throw if no parameter is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument();
        }).to.throw(Error, 'Missing or invalid `entries` parameter');
    });

    it('should throw if an invalid parameter is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([]);
        }).to.throw(Error, 'Missing or invalid `entries` parameter');
    });

    it('should throw if an entry of an incorrect type (!object) is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument(['bla']);
        }).to.throw(Error, 'invalid entry type');
    });

    it('should throw if an entry of an incorrect type (null) is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([null]);
        }).to.throw(Error, 'invalid entry type');
    });

    it('should throw if an entry with an object missing property `msgInfo` is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{}]);
        }).to.throw(Error, 'missing or invalid `msgInfo` property');
    });

    it('should throw if an entry with an object with an invalid `msgInfo` property is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: 'bla'
            }]);
        }).to.throw(Error, 'missing or invalid `msgInfo` property');
    });

    it('should throw if an entry with an object missing property `msgInfo.senderPubKeyHash`is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: {}
            }]);
        }).to.throw(Error, 'missing or invalid `msgInfo.senderPubKeyHash` property');
    });

    it('should throw if an entry with an object with an invalid `msgInfo.senderPubKeyHash` property (invalid base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: {
                    senderPubKeyHash: 'fjsk$*%&*@&%(*&@'
                }
            }]);
        }).to.throw(Error, 'missing or invalid `msgInfo.senderPubKeyHash` property');
    });

    it('should throw if an entry with an object with an invalid `msgInfo.senderPubKeyHash` property (shorter base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: {
                    senderPubKeyHash: Buffer.from('bla').toString('base64')
                }
            }]);
        }).to.throw(Error, 'missing or invalid `msgInfo.senderPubKeyHash` property');
    });

    it('should throw if an entry with an object with an invalid `msgInfo.senderPubKeyHash` property (shorter Buffer) is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: {
                    senderPubKeyHash: Buffer.from('bla')
                }
            }]);
        }).to.throw(Error, 'missing or invalid `msgInfo.senderPubKeyHash` property');
    });

    it('should throw if an entry with an object with an invalid `msgInfo.receiverPubKeyHash` property (invalid base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: 'fjsk$*%&*@&%(*&@'
                }
            }]);
        }).to.throw(Error, 'invalid `msgInfo.receiverPubKeyHash` property');
    });

    it('should throw if an entry with an object with an invalid `msgInfo.receiverPubKeyHash` property (shorter base64 string) is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: Buffer.from('bla').toString('base64')
                }
            }]);
        }).to.throw(Error, 'invalid `msgInfo.receiverPubKeyHash` property');
    });

    it('should throw if an entry with an object with an invalid `msgInfo.receiverPubKeyHash` property (shorter Buffer) is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: Buffer.from('bla')
                }
            }]);
        }).to.throw(Error, 'invalid `msgInfo.receiverPubKeyHash` property');
    });

    it('should throw if an entry with an object missing property `msgDataCid` is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: Buffer.alloc(20, 0xff)
                }
            }]);
        }).to.throw(Error, 'missing or invalid `msgDataCid` property');
    });

    it('should throw if an entry with an object with an invalid `msgDataCid` property is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: {
                    senderPubKeyHash: Buffer.alloc(20, 0xff),
                    receiverPubKeyHash: Buffer.alloc(20, 0xff)
                },
                msgDataCid: Buffer.from('bla')
            }]);
        }).to.throw(Error, 'missing or invalid `msgDataCid` property');
    });

    it('should throw if an entry with an object with an inconsistent value in property `msgEnvCid` is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: sendMsgEnv,
                msgDataCid: logMsgEnvCid
            }]);
        }).to.throw(Error, 'inconsistent `msgDataCid` property: it does not match message data');
    });

    it('should successfully return when passing one entry with a `msgInfo` object', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: {
                    senderPubKeyHash: sendMsgEnv.senderPubKeyHash,
                    receiverPubKeyHash: sendMsgEnv.receiverPubKeyHash
                },
                msgDataCid: sendMsgEnvCid
            }]);
        }).to.not.throw();
    });

    it('should successfully return when passing one entry with a `msgInfo` object with no `receiverPubKeyHash` property', function () {
        expect(() => {new ctnOffChainLib.BatchDocument([{
                msgInfo: {
                    senderPubKeyHash: logMsgEnv.senderPubKeyHash
                },
                msgDataCid: logMsgEnvCid
            }]);
        }).to.not.throw();
    });

    it('should successfully return when passing one entry with a MessageEnvelope `msgInfo`', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: logMsgEnv,
                msgDataCid: logMsgEnvCid
            }]);
        }).to.not.throw();
    });

    it('should successfully return when passing one entry with a MessageReceipt `msgInfo`', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: sendMsgRcpt,
                msgDataCid: sendMsgRcptCid
            }]);
        }).to.not.throw();
    });

    it('should throw if any entry is not valid even if there are valid entries', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: sendMsgRcpt,
                msgDataCid: sendMsgRcptCid
            }, {
                msgInfo: {}
            }]);
        }).to.throw(Error, 'Invalid entry #2');
    });

    it('should throw if an entry with a duplicate `msgDataCid` property is passed', function () {
        expect(() => {
            new ctnOffChainLib.BatchDocument([{
                msgInfo: sendMsgRcpt,
                msgDataCid: sendMsgRcptCid
            }, {
                msgInfo: {
                    senderPubKeyHash: sendMsgRcpt.senderPubKeyHash,
                    receiverPubKeyHash: sendMsgRcpt.receiverPubKeyHash
                },
                msgDataCid: sendMsgRcptCid
            }]);
        }).to.throw(Error, 'duplicate `msgDataCid` property value');
    });
});

describe('Batch Document instance', function () {
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
    const sendMsgEnvCid = new CID(0, 'dag-pb', multihashing(sendMsgEnv.buffer,'sha2-256'));
    const logMsgEnv = new ctnOffChainLib.MessageEnvelope({
        msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
        msgOpts: 0x01,
        senderPubKeyHash: hashPubKey(keyPair1),
        timestamp: new Date('2019-11-09').getTime(),
        stoProviderCode: 0x02,
        msgRef: msgCid.buffer
    });
    const logMsgEnvCid = new CID(0, 'dag-pb', multihashing(logMsgEnv.buffer,'sha2-256'));
    const sendMsgRcpt = new ctnOffChainLib.MessageReceipt({
        msgInfo: sendMsgEnv,
        timestamp: new Date('2019-11-09').getTime(),
        msgEnvCid: sendMsgEnvCid
    });
    const sendMsgRcptCid = new CID(0, 'dag-pb', multihashing(sendMsgRcpt.buffer,'sha2-256'));

    describe('with only message data (MessageEnvelope or MessageReceipt) instances', function () {
        const batchDoc = new ctnOffChainLib.BatchDocument([{
            msgInfo: sendMsgEnv,
            msgDataCid: sendMsgEnvCid
        }, {
            msgInfo: logMsgEnv,
            msgDataCid: logMsgEnvCid
        }, {
            msgInfo: sendMsgRcpt,
            msgDataCid: sendMsgRcptCid
        }]);

        it('should correctly report that it is not yet built', function () {
            expect(batchDoc.isBuilt).to.be.false;
        });

        it('should correctly return no hex value', function () {
            expect(batchDoc.hex).to.be.undefined;
        });

        it('should return the correct Merkle root', function () {
            expect(batchDoc.merkleRoot.equals(Buffer.from('01c596972b825bcd47fcd62eb2881c6fa65636779f37c44e8d7321162b3142ddba', 'hex'))).to.be.true;
        });

        it('should correctly report that all message data are checked', function () {
            expect(batchDoc.isAllMessageDataChecked()).to.be.true;
        });

        it('should correctly return no indices for message data to be checked', function () {
            expect(batchDoc.indicesEntryToCheckMessageData.length === 0).to.be.true;
        });

        it('should throw if an invalid message data is passed to be checked', function () {
            expect(() => {
                batchDoc.isMessageDataInBatch('bla');
            }).to.throw(Error, 'Invalid message data (envelope or receipt) CID');
        });

        it('should correctly report that message data is in batch', function () {
            [sendMsgEnvCid, logMsgEnvCid, sendMsgRcptCid].forEach((msgDataCid => {
                expect(batchDoc.isMessageDataInBatch(msgDataCid)).to.be.true;
            }));
        });

        it('should correctly report that message data is not in batch', function () {
            expect(batchDoc.isMessageDataInBatch(msgCid)).to.be.false;
        });

        describe('after building it', function () {
            const batchDocHex = '1f8b080000000000001335cedb6e82300000d07fe9eb489c8c9b263e701d41408a3210e3834241562bb3052c2efbf799997dc049ce3720acb60edd01cc77009224a0ee474270701b6a54290466a61c43d84c4747e1788c50b4ecd6d0cb34237281f0006bcbf78991e86b6f409ce71594a4d6b46c5f2fc32fa2991e56c76a29cd6427bbf67f2051b88b13586eb9ba89b3f7e6a43383487205a91e3948c39bbeec1c29f570205fc15e000c5d4a44d9a3b703f1aa3ee6b3d6976eb63834839e9a012d4ede994fda051076afc25410f7fb07a2a840cdf0cf366faac354645b6322dfc5abdb5cc2de7ea177e4d54ff64404517c4671db76600ef4224dcf636fa6dad49d84db9eb5757154f234bca02ad4e2d567169c9c8671d8890af8f905f61fffe546010000';

            it('should correclty build', function () {
                expect(() => {
                    batchDoc.build();
                }).to.not.throw();
            });

            it('should correctly report that it is already built', function () {
                expect(batchDoc.isBuilt).to.be.true;
            });

            it('should return the correct hex value', function () {
                expect(batchDoc.hex).to.equal(batchDocHex);
            });

            it('should should not fail when trying to rebuild it', function () {
                expect(() => {
                    batchDoc.build();
                }).to.not.throw();
            });
        });
    });

    describe('with only `msgInfo` objects', function () {
        const batchDoc = new ctnOffChainLib.BatchDocument([{
            msgInfo: {
                senderPubKeyHash: sendMsgEnv.senderPubKeyHash,
                receiverPubKeyHash: sendMsgEnv.receiverPubKeyHash
            },
            msgDataCid: sendMsgEnvCid
        }, {
            msgInfo: {
                senderPubKeyHash: logMsgEnv.senderPubKeyHash
            },
            msgDataCid: logMsgEnvCid
        }, {
            msgInfo: {
                senderPubKeyHash: sendMsgRcpt.senderPubKeyHash,
                receiverPubKeyHash: sendMsgRcpt.receiverPubKeyHash
            },
            msgDataCid: sendMsgRcptCid
        }]);

        it('should correctly report that not all message data are checked', function () {
            expect(batchDoc.isAllMessageDataChecked()).to.be.false;
        });

        it('should correctly return the indices for message data yet to be checked', function () {
            expect(batchDoc.indicesEntryToCheckMessageData).to.deep.equal([0, 1, 2]);
        });

        describe('checking message data', function () {
            const keyPair3 = bitcoinLib.ECPair.makeRandom();
            const keyPair4 = bitcoinLib.ECPair.makeRandom();
            const msgCid2 = new CID(0, 'dag-pb', multihashing(Buffer.from('Another test message'),'sha2-256'));
            const sendMsgEnv2 = new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: hashPubKey(keyPair1),
                receiverPubKeyHash: hashPubKey(keyPair3),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: msgCid2.buffer
            });
            const sendMsgEnv3 = new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: hashPubKey(keyPair1),
                receiverPubKeyHash: hashPubKey(keyPair2),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: msgCid2.buffer
            });
            const sendMsgEnv4 = new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.sendMessage,
                msgOpts: 0x03,
                senderPubKeyHash: hashPubKey(keyPair3),
                receiverPubKeyHash: hashPubKey(keyPair4),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: msgCid2.buffer
            });
            const logMsgEnv2 = new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
                msgOpts: 0x01,
                senderPubKeyHash: hashPubKey(keyPair2),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: msgCid2.buffer
            });
            const logMsgEnv3 = new ctnOffChainLib.MessageEnvelope({
                msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
                msgOpts: 0x01,
                senderPubKeyHash: hashPubKey(keyPair1),
                timestamp: new Date('2019-11-09').getTime(),
                stoProviderCode: 0x02,
                msgRef: msgCid2.buffer
            });

            it('should throw if it is passed less message data items than the number of entries', function () {
                expect(() => {
                    batchDoc.checkMessageData(sendMsgEnv);
                }).to.throw(Error, 'Number of message data items do not match number of entries');
            });

            it('should fail with different types of error (#1)', function () {
                const result = batchDoc.checkMessageData([
                    sendMsgEnv2,
                    logMsgEnv3,
                    'bla'
                ]);

                expect(result).to.be.false;
                expect(batchDoc.listCheckMsgDataError).to.deep.equal([
                    'Invalid message data: it does not match sender and/or receiver',
                    'Invalid message data: it does not match message data CID',
                    'Invalid message data: not an instance of MessageEnvelope nor MessageReceipt'
                ]);
            });

            it('should fail with different types of error (#2)', function () {
                const result = batchDoc.checkMessageData([
                    logMsgEnv,
                    sendMsgEnv,
                    undefined
                ]);

                expect(result).to.be.false;
                expect(batchDoc.listCheckMsgDataError).to.deep.equal([
                    'Invalid message data: it does not match sender and/or receiver',
                    'Invalid message data: it does not match sender and/or receiver',
                    'Invalid message data: not an instance of MessageEnvelope nor MessageReceipt'
                ]);
            });

            it('should fail with different types of error (#3)', function () {
                const result = batchDoc.checkMessageData([
                    sendMsgEnv3,
                    logMsgEnv2,
                    undefined
                ]);

                expect(result).to.be.false;
                expect(batchDoc.listCheckMsgDataError).to.deep.equal([
                    'Invalid message data: it does not match message data CID',
                    'Invalid message data: it does not match sender and/or receiver',
                    'Invalid message data: not an instance of MessageEnvelope nor MessageReceipt'
                ]);
            });

            it('should fail with different types of error (#4)', function () {
                const result = batchDoc.checkMessageData([
                    sendMsgEnv4,
                    sendMsgEnv2,
                    undefined
                ]);

                expect(result).to.be.false;
                expect(batchDoc.listCheckMsgDataError).to.deep.equal([
                    'Invalid message data: it does not match sender and/or receiver',
                    'Invalid message data: it does not match sender and/or receiver',
                    'Invalid message data: not an instance of MessageEnvelope nor MessageReceipt'
                ]);
            });

            it('should succeed', function () {
                const result = batchDoc.checkMessageData([
                    sendMsgEnv,
                    logMsgEnv,
                    sendMsgRcpt
                ]);

                expect(result).to.be.true;
                expect(batchDoc.listCheckMsgDataError).to.deep.equal([
                    undefined,
                    undefined,
                    undefined
                ]);
            });

            it('should correctly report that all message data are checked', function () {
                expect(batchDoc.isAllMessageDataChecked()).to.be.true;
            });

            it('should correctly return no indices for message data to be checked', function () {
                expect(batchDoc.indicesEntryToCheckMessageData.length === 0).to.be.true;
            });

            it('should fail trying to check a message data for an entry that is already checked', function () {
                const result = batchDoc.checkMessageData([
                    sendMsgEnv,
                    undefined,
                    undefined
                ]);

                expect(result).to.be.false;
                expect(batchDoc.listCheckMsgDataError).to.deep.equal([
                    'Message data already checked for entry',
                    undefined,
                    undefined
                ]);
            });
        });
    });

    describe('with a mix of message data (MessageEnvelope or MessageReceipt) instances and `msgInfo` objects', function () {
        const batchDoc = new ctnOffChainLib.BatchDocument([{
            msgInfo: sendMsgEnv,
            msgDataCid: sendMsgEnvCid
        }, {
            msgInfo: {
                senderPubKeyHash: logMsgEnv.senderPubKeyHash
            },
            msgDataCid: logMsgEnvCid
        }, {
            msgInfo: sendMsgRcpt,
            msgDataCid: sendMsgRcptCid
        }]);

        it('should correctly report that not all message data are checked', function () {
            expect(batchDoc.isAllMessageDataChecked()).to.be.false;
        });

        it('should correctly return the indices for message data yet to be checked', function () {
            expect(batchDoc.indicesEntryToCheckMessageData).to.deep.equal([1]);
        });
    });
});

describe('Parse Batch Document', function () {
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
    const sendMsgEnvCid = new CID(0, 'dag-pb', multihashing(sendMsgEnv.buffer,'sha2-256'));
    const logMsgEnv = new ctnOffChainLib.MessageEnvelope({
        msgType: ctnOffChainLib.MessageEnvelope.msgType.logMessage,
        msgOpts: 0x01,
        senderPubKeyHash: hashPubKey(keyPair1),
        timestamp: new Date('2019-11-09').getTime(),
        stoProviderCode: 0x02,
        msgRef: msgCid.buffer
    });
    const logMsgEnvCid = new CID(0, 'dag-pb', multihashing(logMsgEnv.buffer,'sha2-256'));
    const sendMsgRcpt = new ctnOffChainLib.MessageReceipt({
        msgInfo: sendMsgEnv,
        timestamp: new Date('2019-11-09').getTime(),
        msgEnvCid: sendMsgEnvCid
    });
    const sendMsgRcptCid = new CID(0, 'dag-pb', multihashing(sendMsgRcpt.buffer,'sha2-256'));

    const batchDoc = new ctnOffChainLib.BatchDocument([{
        msgInfo: sendMsgEnv,
        msgDataCid: sendMsgEnvCid
    }, {
        msgInfo: logMsgEnv,
        msgDataCid: logMsgEnvCid
    }, {
        msgInfo: sendMsgRcpt,
        msgDataCid: sendMsgRcptCid
    }]);
    batchDoc.build();
    const batchDocBuf = batchDoc.buffer;

    it('should throw if incorrect parameter type is passed', function () {
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer('bla');
        }).to.throw(TypeError, 'Invalid argument type; expected Buffer');
    });

    it('should throw if data passed is not compressed', function () {
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from('bla'));
        }).to.throw(Error, 'Data is not compressed as expected');
    });

    it('should throw if an invalid JSON is passed', function () {
        const data = zlib.gzipSync(Buffer.from(''));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Data is not a valid JSON object');
    });

    it('should throw if an invalid JSON (non-object) is passed', function () {
        const data = zlib.gzipSync(Buffer.from('"bla"'));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Data is not a valid JSON object');
    });

    it('should throw if an invalid JSON (null) is passed', function () {
        const data = zlib.gzipSync(Buffer.from('null'));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Data is not a valid JSON object');
    });

    it('should throw if an invalid batch document object (missing properties #1) is passed', function () {
        const doc = {
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Invalid batch document object');
    });

    it('should throw if an invalid batch document object (properties with incorrect type) is passed', function () {
        const doc = {
            msgData: 'bla',
            senders: 'bla',
            receivers: 'bla',
            merkleRoot: null
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Invalid batch document object');
    });

    it('should throw if a batch document object with an invalid `msgData` property is passed', function () {
        const doc = {
            msgData: [],
            senders:  [],
            receivers: [],
            merkleRoot: 'bla'
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Invalid `msgData` property of batch document object');
    });

    it('should throw if a batch document object with an invalid `senders` property is passed', function () {
        const doc = {
            msgData: ['bla'],
            senders:  [1],
            receivers: [],
            merkleRoot: 'bla'
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Invalid `senders` property of batch document object');
    });

    it('should throw if a batch document object with an invalid `receivers` property is passed', function () {
        const doc = {
            msgData: ['bla'],
            senders:  [['bla', [0]]],
            receivers: [1],
            merkleRoot: 'bla'
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Invalid `receivers` property of batch document object');
    });

    it('should throw if a batch document object with an inconsistent (invalid list of indices) list of senders is passed', function () {
        const doc = {
            msgData: ['bla'],
            senders:  [['bla', 0]],
            receivers: [['bla', [0]]],
            merkleRoot: 'bla'
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Invalid list of indices for sender');
    });

    it('should throw if a batch document object with an inconsistent (invalid index) list of senders is passed', function () {
        const doc = {
            msgData: ['bla'],
            senders:  [['bla', [5]]],
            receivers: [['bla', [0]]],
            merkleRoot: 'bla'
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Invalid index for sender');
    });

    it('should throw if a batch document object with an inconsistent (duplicate sender) list of senders is passed', function () {
        const doc = {
            msgData: ['bla1', 'bla2'],
            senders:  [['bla', [0, 0]]],
            receivers: [['bla', [0]]],
            merkleRoot: 'bla'
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Duplicate sender for entry');
    });

    it('should throw if a batch document object with an inconsistent (invalid list of indices) list of receivers is passed', function () {
        const doc = {
            msgData: ['bla'],
            senders:  [['bla', [0]]],
            receivers: [['bla', 0]],
            merkleRoot: 'bla'
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Invalid list of indices for receiver');
    });

    it('should throw if a batch document object with an inconsistent (invalid index) list of receivers is passed', function () {
        const doc = {
            msgData: ['bla'],
            senders:  [['bla', [0]]],
            receivers: [['bla', [5]]],
            merkleRoot: 'bla'
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Invalid index for receiver');
    });

    it('should throw if a batch document object with an inconsistent (duplicate receiver) list of receivers is passed', function () {
        const doc = {
            msgData: ['bla1', 'bla2'],
            senders:  [['bla', [0, 1]]],
            receivers: [['bla', [0, 0]]],
            merkleRoot: 'bla'
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Duplicate receiver for entry');
    });

    it('should throw if a batch document object with invalid entries is passed', function () {
        const doc = {
            msgData: ['bla'],
            senders:  [['bla', [0]]],
            receivers: [['bla', [0]]],
            merkleRoot: 'bla'
        };
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Invalid batch document entries');
    });

    it('should throw if a batch document object with inconsistent Merkle root hash is passed', function () {
        const doc = batchDoc.doc;
        doc.merkleRoot = 'bla';
        const data = zlib.gzipSync(Buffer.from(JSON.stringify(doc)));
        expect(() => {
            ctnOffChainLib.BatchDocument.fromBuffer(Buffer.from(data));
        }).to.throw(Error, 'Inconsistent Merkle root hash in batch document');
    });

    it('should return an object that matches original one', function () {
        const batchDoc2 = ctnOffChainLib.BatchDocument.fromBuffer(batchDocBuf);

        expect(batchDoc2.hex).to.equals(batchDoc.hex);
    });

    describe('from hex', function () {
        it('should return an object that matches original one', function () {
            const batchDoc2 = ctnOffChainLib.BatchDocument.fromHex(batchDocBuf.toString('hex'));

            expect(batchDoc2.hex).to.equals(batchDoc.hex);
        });
    });
});
