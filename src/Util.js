const CID = require('cids');
const BigNumber = require('bignumber.js');
const bitcoinLib = require('bitcoinjs-lib');

const MAX_TIMESTAMP = 8640000000000000;     // 100,000,000 years (in milliseconds) after Unix's epoch
const MIN_TIMESTAMP = -MAX_TIMESTAMP;       // 100,000,000 years (in milliseconds) before Unix's epoch
const COMPRESSED_PUB_KEY_LENGTH = 33;

module.exports = {
    dummyPubKeyHash: Buffer.alloc(20, 0x00),
    validatePubKeyHash(pubKeyHash) {
        let bufPubKeyHash;

        if (Buffer.isBuffer(pubKeyHash)) {
            bufPubKeyHash = pubKeyHash;
        }
        else if (typeof pubKeyHash === 'string') {
            // Public key hash should be base64 encoded. Try to decode it
            const decPubKeyHash = Buffer.from(pubKeyHash, 'base64');

            if (decPubKeyHash.toString('base64') === pubKeyHash) {
                bufPubKeyHash = decPubKeyHash;
            }
        }

        if (bufPubKeyHash && bufPubKeyHash.byteLength === 20) {
            return bufPubKeyHash;
        }
    },
    isValidTimestamp(timestamp) {
        return Number.isInteger(timestamp) && timestamp >= MIN_TIMESTAMP && timestamp <= MAX_TIMESTAMP;
    },
    validateCid(cid) {
        let validCid;

        try {
            validCid = new CID(cid);
        }
        catch (err) {}

        return validCid;
    },
    keyPairFromPublicKey(pubKey) {
        const opts = pubKey.byteLength > COMPRESSED_PUB_KEY_LENGTH ? {compressed: false} : undefined;

        return bitcoinLib.ECPair.fromPublicKey(pubKey, opts);
    },
    writeUInt64BE(num, buf, offset) {
        const bnNum = new BigNumber(num);
        const bnUpperValue = bnNum.dividedToIntegerBy(0x100000000);
        offset = buf.writeUInt32BE(bnUpperValue.toNumber(), offset);
        offset = buf.writeUInt32BE(bnNum.minus(bnUpperValue.times(0x100000000)).toNumber(), offset);

        return offset;
    },
    readUInt64BE(buf, offset) {
        const bnUpperValue = new BigNumber(buf.readUInt32BE(offset));
        return bnUpperValue.times(0x100000000).plus(buf.readUInt32BE(offset + 4)).toNumber();
    }
};

module.exports.writeInt64BE = function writeInt64BE(num, buf, offset) {
    if (num >= 0) {
        return module.exports.writeUInt64BE(num, buf,offset);
    }

    num = -num;

    const bnNum = new BigNumber(num);
    const bnUpperValue = bnNum.dividedToIntegerBy(0x100000000);
    const bnLowerValue = bnNum.minus(bnUpperValue.times(0x100000000));

    if (bnLowerValue.isZero()) {
        // Write 2's complement (i.e. -n) of upper value
        offset = buf.writeInt32BE(bnUpperValue.negated().toNumber(), offset);
    }
    else {
        // Write 1's complement of upper value
        offset = buf.writeUInt32BE(new BigNumber('ffffffff', 16).minus(bnUpperValue).toNumber(), offset);
    }

    // Write 2's complement (i.e. -n) of lower value
    offset = buf.writeInt32BE(bnLowerValue.negated().toNumber(), offset);

    return offset;
};

module.exports.readInt64BE = function readInt64BE(buf, offset) {
    if ((buf[offset] & 0x80) === 0) {
        // Positive number
        return module.exports.readUInt64BE(buf, offset);
    }

    // Negative number
    const lowerValue = -buf.readInt32BE(offset + 4);
    let bnUpperValue;

    if (lowerValue === 0) {
        bnUpperValue = new BigNumber(-buf.readInt32BE(offset));
    }
    else {
        bnUpperValue = new BigNumber('ffffffff', 16).minus(buf.readUInt32BE(offset));
    }

    return bnUpperValue.times(0x100000000).plus(lowerValue).negated().toNumber();
};
