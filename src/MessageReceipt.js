const bitcoinLib = require('bitcoinjs-lib');
const varint = require('varint');
const multihashing = require('multihashing');
const MessageEnvelope = require('./MessageEnvelope');
const Util = require('./Util');

const structID = 0x52;
const initVersion = 0x01;
const currentVersion = initVersion;
const headerFixedLength = 2 + (20 * 2) + 8;
const minHeaderLength = 1 + headerFixedLength + 3;
const minSignDataLength = 1 + 1 + 33;

class MessageReceipt {
    /**
     * Class constructor
     * @param rcptInfo (Object) Object containing information describing the message receipt to create, with the
     *                           following properties:
     *                           - msgInfo (MessageEnvelope|Object) Info about the message for which this receipt is issued.
     *                               Can be either an instance of MessageEnvelope or a literal object with the following properties:
     *                               - senderPubKeyHash (String|Buffer) The public key hash of the Catenis device that sent the message
     *                               - receiverPubKeyHash (String|Buffer) The public key hash of the Catenis device to which the message was sent
     *                           - timestamp (Integer) (optional) The timestamp (milliseconds from Unix's epoch) when the message receipt was created.
     *                               If not specified, the current time is used
     *                           - msgEnvCid (String|Buffer|CID) The IPFS CID of the message envelope of the message for which this receipt is issued
     */
    constructor(rcptInfo) {
        // Validate parameter
        if (typeof rcptInfo !== 'object' || rcptInfo === null) {
            throw new Error('Missing or invalid `rcptInfo` parameter');
        }

        const rcptInfoErrors = [];
        let msgInfoError = false;

        if (rcptInfo.msgInfo instanceof MessageEnvelope) {
            this.msgEnv = rcptInfo.msgInfo;

            if (!isValidMsgEnvelope(this.msgEnv)) {
                rcptInfoErrors.push('inconsistent `msgInfo` property: message does not require receipt');
            }
            else {
                this.senderPubKeyHash = this.msgEnv.senderPubKeyHash;
                this.receiverPubKeyHash = this.msgEnv.receiverPubKeyHash;
            }
        }
        else if (typeof rcptInfo.msgInfo !== 'object' || rcptInfo.msgInfo === null) {
            rcptInfoErrors.push('missing or invalid `msgInfo` property');
            msgInfoError = true;
        }

        if (!this.msgEnv && !msgInfoError) {
            this.senderPubKeyHash = Util.validatePubKeyHash(rcptInfo.msgInfo.senderPubKeyHash);

            if (!this.senderPubKeyHash) {
                rcptInfoErrors.push('missing or invalid `msgInfo.senderPubKeyHash` property');
            }

            this.receiverPubKeyHash = Util.validatePubKeyHash(rcptInfo.msgInfo.receiverPubKeyHash);

            if (!this.receiverPubKeyHash) {
                rcptInfoErrors.push('missing or invalid `msgInfo.receiverPubKeyHash` property');
            }
        }

        if (rcptInfo.timestamp) {
            if (!Util.isValidTimestamp(rcptInfo.timestamp)) {
                rcptInfoErrors.push('invalid `timestamp` property');
            }
            else {
                this.timestamp = rcptInfo.timestamp;
            }
        }
        else {
            this.timestamp = Date.now();
        }

        this.msgEnvCid = Util.validateCid(rcptInfo.msgEnvCid);

        if (!this.msgEnvCid) {
            rcptInfoErrors.push('missing or invalid `msgEnvCid` property');
        }
        else if (this.msgEnv && !multihashing.verify(this.msgEnvCid.multihash, this.msgEnv.buffer)) {
            rcptInfoErrors.push('inconsistent `msgEnvCid` property: it does not match message envelope');
        }

        if (rcptInfoErrors.length > 0) {
            throw new Error('Invalid `rcptInfo` parameter: ' + rcptInfoErrors.join('; '));
        }

        // Encode data structure
        const fixedHeader = Buffer.alloc(headerFixedLength);
        let offset = 0;

        offset = fixedHeader.writeUInt8(structID, offset);
        this.version = currentVersion;
        offset = fixedHeader.writeUInt8(this.version, offset);
        offset += this.senderPubKeyHash.copy(fixedHeader, offset);
        offset += this.receiverPubKeyHash.copy(fixedHeader, offset);
        Util.writeInt64BE(this.timestamp, fixedHeader, offset);

        const header = Buffer.concat([fixedHeader, this.msgEnvCid.buffer]);

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

    get base64() {
        return this.buffer.toString('base64');
    }

    get isMessageChecked() {
        return !!this.msgEnv;
    }

    get isSigned() {
        return this.hasSignature;
    }

    checkMessage(msgEnv) {
        // Reset error
        this.checkMessageError = undefined;

        if (this.msgEnv) {
            this.checkMessageError = 'Message already checked for receipt';
        }

        if (!this.checkMessageError && !(msgEnv instanceof MessageEnvelope)) {
            this.checkMessageError = 'Invalid message: not an instance of MessageEnvelope';
        }

        if (!this.checkMessageError && !isValidMsgEnvelope(msgEnv)) {
            this.checkMessageError = 'Invalid message: it does not require receipt';
        }

        if (!this.checkMessageError && (!msgEnv.senderPubKeyHash.equals(this.senderPubKeyHash) || !msgEnv.receiverPubKeyHash.equals(this.receiverPubKeyHash))) {
            this.checkMessageError = 'Invalid message: it does not match sender and/or receiver';
        }

        if (!this.checkMessageError && !multihashing.verify(this.msgEnvCid.multihash, msgEnv.buffer)) {
            this.checkMessageError = 'Invalid message: it does not match message envelope CID';
        }

        if (!this.checkMessageError) {
            // Message successfully checked
            this.msgEnv = msgEnv;
            return true;
        }
        else {
            return false;
        }
    }

    sign(keyPair) {
        if (!this.hasSignature) {
            if (!keyPair.compressed) {
                throw new Error('Invalid public key format; it should be compressed');
            }

            // Make sure that passed in key pair matches message receiver's public key hash
            if (!bitcoinLib.crypto.hash160(keyPair.publicKey).equals(this.receiverPubKeyHash)) {
                throw new Error('Passed in key pair does not match message receiver\'s public key hash');
            }

            this.signature = keyPair.sign(bitcoinLib.crypto.sha256(this.header));
            this.receiverPubKey = keyPair.publicKey;

            this.buffer = Buffer.concat([
                this.header,
                Buffer.from(varint.encode(this.signature.byteLength)),
                this.signature,
                this.receiverPubKey
            ]);

            this.hasSignature = true;
        }
    }

    verifySignature() {
        if (this.hasSignature) {
            try {
                const keyPair = Util.keyPairFromPublicKey(this.receiverPubKey);

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
        const senderPubKeyHash = buf.slice(offset, offset + 20);
        offset += 20;
        const receiverPubKeyHash = buf.slice(offset, offset + 20);
        offset += 20;
        const timestamp = Util.readInt64BE(buf, offset);
        offset += 8;
        const msgEnvCid = buf.slice(offset, headerLength);
        offset = headerLength;

        const headerErrors = [];

        if (!isValidStructIdByte(structIdByte)) {
            headerErrors.push('invalid structure ID');
        }

        if (!isValidVersionByte(versionByte)) {
            headerErrors.push('invalid version byte');
        }

        if (!Util.isValidTimestamp(timestamp)) {
            headerErrors.push('invalid timestamp');
        }

        const rcptInfo = {
            msgEnvCid: Util.validateCid(msgEnvCid)
        };

        if (!rcptInfo.msgEnvCid) {
            headerErrors.push('invalid message content CID');
        }

        if (headerErrors.length > 0) {
            throw new Error('Inconsistent header data: ' + headerErrors.join('; '));
        }

        rcptInfo.msgInfo = {
            senderPubKeyHash: senderPubKeyHash,
            receiverPubKeyHash: receiverPubKeyHash
        };
        rcptInfo.timestamp = timestamp;

        const msgRcpt = new MessageReceipt(rcptInfo);

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

            msgRcpt.signature = bufSig.slice(lenPrefixLength, lenPrefixLength + signDataLength);

            if (msgRcpt.signature.byteLength < signDataLength) {
                throw new Error('Inconsistent signature data: signature shorter than expected');
            }

            offset += lenPrefixLength + signDataLength;
            msgRcpt.receiverPubKey = bufSig.slice(offset);

            if (msgRcpt.receiverPubKey.byteLength === 0) {
                throw new Error('Inconsistent signature data: missing public key');
            }

            // Validate message receiver public key
            let keyPair;

            try {
                keyPair = Util.keyPairFromPublicKey(msgRcpt.receiverPubKey);
            }
            catch (err) {
                throw new Error('Inconsistent signature data: invalid public key')
            }

            if (!keyPair.compressed) {
                throw new Error('Inconsistent signature data: invalid public key format; it should be compressed');
            }

            if (!bitcoinLib.crypto.hash160(keyPair.publicKey).equals(msgRcpt.receiverPubKeyHash)) {
                throw new Error('Inconsistent signature data: public key does not match message receiver\'s public key hash');
            }

            // Add signature data
            msgRcpt.buffer = Buffer.concat([
                msgRcpt.header,
                Buffer.from(varint.encode(msgRcpt.signature.byteLength)),
                msgRcpt.signature,
                msgRcpt.receiverPubKey
            ]);

            msgRcpt.hasSignature = true;
        }

        return msgRcpt;
    }

    static fromHex(hex) {
        return MessageReceipt.fromBuffer(Buffer.from(hex, 'hex'));
    }

    static fromBase64(base64) {
        return MessageReceipt.fromBuffer(Buffer.from(base64, 'base64'));
    }
}

function isValidMsgEnvelope(msgEnv) {
    return msgEnv.msgType === MessageEnvelope.msgType.sendMessage && msgEnv.isMessageWithReadConfirmation;
}

function isValidStructIdByte(byte) {
    return byte === structID;
}

function isValidVersionByte(byte) {
    return byte >= initVersion && byte <= currentVersion;
}

module.exports = MessageReceipt;