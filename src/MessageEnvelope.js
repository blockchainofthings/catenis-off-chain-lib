const bitcoinLib = require('bitcoinjs-lib');
const varint = require('varint');
const Util = require('./Util');

const structID = 0x45;
const initVersion = 0x01;
const currentVersion = initVersion;
const headerFixedLength = 4 + (20 * 2) + 8 + 1;
const minHeaderLength = 1 + headerFixedLength + 3;
const minSignDataLength = 1 + 1 + 33;

class MessageEnvelope {
    /**
     * Class constructor
     * @param msgInfo (Object) Object containing information describing the message envelope to create, with the
     *                          following properties:
     *                          - msgType (Message.msgType) The message type
     *                          - msgOpts (Message.msgOptions) A bitwise data structure specifying the options for the message
     *                          - senderPubKeyHash (String|Buffer) The public key hash of the Catenis device that is sending the message
     *                          - receiverPubKeyHash (String|Buffer) (optional) The public key hash of the Catenis device to which message is being sent
     *                          - timestamp (Integer) (optional) The timestamp (milliseconds from Unix's epoch) when the message was created.
     *                              If not specified, the current time is used
     *                          - stoProviderCode (Integer) One-byte code identifying the Catenis message storage provider used to store the message's content (in an external storage)
     *                          - msgRef (Buffer) The reference (as returned by the storage provider) that points to the message’s content in the external storage
     */
    constructor(msgInfo) {
        // Validate parameter
        if (typeof msgInfo !== 'object' || msgInfo === null) {
            throw new Error('Missing or invalid `msgInfo` parameter');
        }

        const msgInfoErrors = [];

        if (!isValidMsgType(msgInfo.msgType)) {
            msgInfoErrors.push('missing or invalid `msgType` property');
        }
        else {
            this.msgType = msgInfo.msgType;
        }

        if (!isValidMsgOpts(msgInfo.msgOpts, this.msgType)) {
            msgInfoErrors.push('missing or invalid `msgOpts` property');
        }
        else {
            this.msgOpts = msgInfo.msgOpts;
        }

        this.senderPubKeyHash = Util.validatePubKeyHash(msgInfo.senderPubKeyHash);

        if (!this.senderPubKeyHash) {
            msgInfoErrors.push('missing or invalid `senderPubKeyHash` property');
        }

        if (this.msgType === MessageEnvelope.msgType.sendMessage) {
            this.receiverPubKeyHash = Util.validatePubKeyHash(msgInfo.receiverPubKeyHash);

            if (!this.receiverPubKeyHash) {
                msgInfoErrors.push('missing or invalid `receiverPubKeyHash` property');
            }
        }

        if ('timestamp' in msgInfo) {
            if (!Util.isValidTimestamp(msgInfo.timestamp)) {
                msgInfoErrors.push('invalid `timestamp` property');
            }
            else {
                this.timestamp = msgInfo.timestamp;
            }
        }
        else {
            this.timestamp = Date.now();
        }

        this.stoProvider = getStoProviderByCode(msgInfo.stoProviderCode);

        if (!this.stoProvider) {
            msgInfoErrors.push('missing or invalid `stoProviderCode` property');
        }
        else {
            if (!isValidMsgReference(this.stoProvider, msgInfo.msgRef)) {
                msgInfoErrors.push('missing or invalid `msgRef` property');
            }
            else {
                this.msgRef = msgInfo.msgRef;
            }
        }

        if (msgInfoErrors.length > 0) {
            throw new Error('Invalid `msgInfo` parameter: ' + msgInfoErrors.join('; '));
        }

        // Encode data structure
        const fixedHeader = Buffer.alloc(headerFixedLength);
        let offset = 0;

        offset = fixedHeader.writeUInt8(structID, offset);
        this.version = currentVersion;
        offset = fixedHeader.writeUInt8(this.version, offset);
        offset = fixedHeader.writeUInt8(this.msgType.byteId, offset);
        offset = fixedHeader.writeUInt8(this.msgOpts, offset);
        offset += this.senderPubKeyHash.copy(fixedHeader, offset);
        offset += (this.receiverPubKeyHash ? this.receiverPubKeyHash : Util.dummyPubKeyHash).copy(fixedHeader, offset);
        offset = Util.writeInt64BE(this.timestamp, fixedHeader, offset);
        fixedHeader.writeUInt8(this.stoProvider.byteCode, offset);

        const header = Buffer.concat([fixedHeader, this.msgRef]);

        // Add header length prefix
        let lenPrefixLength = 1;

        while (varint.encodingLength(header.byteLength + lenPrefixLength) !== lenPrefixLength) {
            lenPrefixLength++;
        }

        this.buffer = this.header = Buffer.concat([Buffer.from(varint.encode(header.byteLength + lenPrefixLength)), header]);

        this.hasSignature = false;
    }

    get hex() {
        return this.buffer.toString('hex');
    }

    isSigned() {
        return this.hasSignature;
    }

    isMessageEncrypted() {
        return !!(this.msgOpts & MessageEnvelope.msgOptions.encryption);
    }

    isMessageWithReadConfirmation() {
        return !!(this.msgOpts & MessageEnvelope.msgOptions.readConfirmation);
    }

    sign(keyPair) {
        if (!this.hasSignature) {
            if (!keyPair.compressed) {
                throw new Error('Invalid public key format; it should be compressed');
            }

            // Make sure that passed in key pair matches message sender's public key hash
            if (!bitcoinLib.crypto.hash160(keyPair.publicKey).equals(this.senderPubKeyHash)) {
                throw new Error('Passed in key pair does not match message sender\'s public key hash');
            }

            this.signature = keyPair.sign(bitcoinLib.crypto.sha256(this.header));
            this.senderPubKey = keyPair.publicKey;

            this.buffer = Buffer.concat([
                this.header,
                Buffer.from(varint.encode(this.signature.byteLength)),
                this.signature,
                this.senderPubKey
            ]);

            this.hasSignature = true;
        }
    }

    verifySignature() {
        if (this.hasSignature) {
            try {
                const keyPair = Util.keyPairFromPublicKey(this.senderPubKey);

                return keyPair.verify(bitcoinLib.crypto.sha256(this.header), this.signature);
            }
            catch (err) {
                return false;
            }
        }
    }

    static fromBuffer(buf) {
        if (!Buffer.isBuffer(buf)) {
            throw new TypeError('Invalid argument type; expected Buffer');
        }

        // Validate data structure header first
        if (buf.byteLength < minHeaderLength) {
            throw new Error('Data buffer too short');
        }

        let offset = 0;
        let headerLength;

        try {
            headerLength = varint.decode(buf, offset);
        }
        catch (err) {
            throw new Error('Invalid header length');
        }

        const lenPrefixLength = varint.decode.bytes;

        if (headerLength - lenPrefixLength < minHeaderLength - 1 || headerLength > buf.byteLength) {
            throw new Error('Inconsistent header length');
        }

        offset += lenPrefixLength;
        const structIdByte = buf.readUInt8(offset++);
        const versionByte = buf.readUInt8(offset++);
        const msgTypeByte = buf.readUInt8(offset++);
        const msgOptsByte = buf.readUInt8(offset++);
        const senderPubKeyHash = buf.slice(offset, offset + 20);
        offset += 20;
        const receiverPubKeyHash = buf.slice(offset, offset + 20);
        offset += 20;
        const timestamp = Util.readInt64BE(buf, offset);
        offset += 8;
        const stoProviderCodeByte = buf.readUInt8(offset++);
        const msgRef = buf.slice(offset, headerLength);
        offset = headerLength;

        const headerErrors = [];

        if (!isValidStructIdByte(structIdByte)) {
            headerErrors.push('invalid structure ID');
        }

        if (!isValidVersionByte(versionByte)) {
            headerErrors.push('invalid version byte');
        }

        const msgInfo = {
            msgType: getMsgTypeByByteId(msgTypeByte)
        };

        if (!msgInfo.msgType) {
            headerErrors.push('invalid message type');
        }

        if (!Util.isValidTimestamp(timestamp)) {
            headerErrors.push('invalid timestamp');
        }

        const stoProvider = getStoProviderByCode(stoProviderCodeByte);

        if (!stoProvider) {
            headerErrors.push('invalid storage provider code');
        }
        else {
            if (!isValidMsgReference(stoProvider, msgRef)) {
                headerErrors.push('invalid message reference');
            }
        }

        if (headerErrors.length > 0) {
            throw new Error('Inconsistent header data: ' + headerErrors.join('; '));
        }

        msgInfo.msgOpts = msgOptsByte;
        msgInfo.senderPubKeyHash = senderPubKeyHash;

        if (!receiverPubKeyHash.equals(Util.dummyPubKeyHash)) {
            msgInfo.receiverPubKeyHash = receiverPubKeyHash;
        }

        msgInfo.timestamp = timestamp;
        msgInfo.stoProviderCode = stoProvider.byteCode;
        msgInfo.msgRef = msgRef;

        const msgEnv = new MessageEnvelope(msgInfo);

        // Check if signature is present in data structure
        const bufSig = buf.slice(offset);

        if (bufSig.byteLength > 0) {
            // Validate signature part of data structure
            if (bufSig.byteLength < minSignDataLength) {
                throw new Error('Signature data too short');
            }

            offset = 0;
            let signDataLength;

            try {
                signDataLength = varint.decode(bufSig, offset);
            }
            catch (err) {
                throw new Error('Invalid signature length');
            }

            const lenPrefixLength = varint.decode.bytes;

            if (signDataLength < 1) {
                throw new Error('Inconsistent signature length');
            }

            msgEnv.signature = bufSig.slice(lenPrefixLength, lenPrefixLength + signDataLength);

            if (msgEnv.signature.byteLength < signDataLength) {
                throw new Error('Inconsistent signature data: signature shorter than expected');
            }

            offset += lenPrefixLength + signDataLength;
            msgEnv.senderPubKey = bufSig.slice(offset);

            if (msgEnv.senderPubKey.byteLength === 0) {
                throw new Error('Inconsistent signature data: missing public key');
            }

            // Validate message sender public key
            let keyPair;

            try {
                keyPair = Util.keyPairFromPublicKey(msgEnv.senderPubKey);
            }
            catch (err) {
                throw new Error('Inconsistent signature data: invalid public key')
            }

            if (!keyPair.compressed) {
                throw new Error('Inconsistent signature data: invalid public key format; it should be compressed');
            }

            if (!bitcoinLib.crypto.hash160(keyPair.publicKey).equals(msgEnv.senderPubKeyHash)) {
                throw new Error('Inconsistent signature data: public key does not match message sender\'s public key hash');
            }

            // Add signature data
            msgEnv.buffer = Buffer.concat([
                msgEnv.header,
                Buffer.from(varint.encode(msgEnv.signature.byteLength)),
                msgEnv.signature,
                msgEnv.senderPubKey
            ]);

            msgEnv.hasSignature = true;
        }

        return msgEnv;
    }

    static fromHex(hex) {
        return MessageEnvelope.fromBuffer(Buffer.from(hex, 'hex'));
    }
}

MessageEnvelope.msgType = Object.freeze({
    logMessage: Object.freeze({
        name: 'log-message',
        description: 'Catenis message used to record data to the blockchain',
        byteId: 0x00
    }),
    sendMessage: Object.freeze({
        name: 'send-message',
        description: 'Catenis message used to record data to the blockchain addressing it to a specific virtual device',
        byteId: 0x01
    })
});

MessageEnvelope.msgOptions = Object.freeze({
    encryption: 0x01,
    readConfirmation: 0x02
});

// NOTE: this should match the definition in Catenis (CatenisMessage.storageProvider)
MessageEnvelope.storageProvider = Object.freeze({
    ipfs2: Object.freeze({
        byteCode: 0x02,
        name: "ipfs",
        description: "IPFS - Interplanetary Filesystem",
        version: 2,
        validator: (ref) => Util.validateCid(ref) !== undefined
    })
});

function isValidMsgType(msgType) {
    return Object.values(MessageEnvelope.msgType).some(type => msgType === type);
}

function isValidMsgOpts(msgOpts, msgType) {
    if (Number.isInteger(msgOpts) && msgOpts >= 0 && msgOpts <= 0xff) {
        const mask = Object.values(MessageEnvelope.msgOptions).reduce((mask, bit) => mask | bit, 0x00);

        if ((mask | msgOpts) === mask) {
            // Make sure that read confirmation is only set for send message
            return !(msgOpts & MessageEnvelope.msgOptions.readConfirmation) || msgType === MessageEnvelope.msgType.sendMessage;
        }
    }

    return false;
}

function getStoProviderByCode(code) {
    return Object.values(MessageEnvelope.storageProvider).find(stoProv => stoProv.byteCode === code);
}

function isValidMsgReference(stoProvider, msgRef) {
    if (Buffer.isBuffer(msgRef) && stoProvider) {
        return stoProvider.validator(msgRef);
    }

    return false;
}

function isValidStructIdByte(byte) {
    return byte === structID;
}

function isValidVersionByte(byte) {
    return byte >= initVersion && byte <= currentVersion;
}

function getMsgTypeByByteId(byte) {
    return Object.values(MessageEnvelope.msgType).find(type => type.byteId === byte);
}

module.exports = MessageEnvelope;