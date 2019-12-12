const util = require('util');
const zlib = require('zlib');
const bitcoinLib = require('bitcoinjs-lib');
const multihashing = require('multihashing');
const merkle = require('merkle-lib');
const merkleProof = require('merkle-lib/proof');
const MessageEnvelope = require('./MessageEnvelope');
const MessageReceipt = require('./MessageReceipt');
const Util = require('./Util');

class BatchDocument {
    /**
     * Class constructor
     * @param entries (Array(Object)) An array of objects containing information describing the message data (either message envelopes or message receipts)
     *                                 to be included in the batch, with the following properties:
     *                                 - msgInfo (MessageEnvelope|MessageReceipt|Object) Information about the message the message envelope or receipt of which is to be added to the batch.
     *                                     Can be either an instance of MessageEnvelope, and instance of MessageReceipt or a literal object with the following properties:
     *                                     - senderPubKeyHash (String|Buffer) The public key hash of the Catenis device that sent the message
     *                                     - receiverPubKeyHash (String|Buffer) (optional) The public key hash of the Catenis device to which the message was sent
     *                                 - msgDataCid (String|Buffer|CID) The IPFS CID of the message envelope or receipt to add to the batch
     */
    constructor(entries) {
        if (!Array.isArray(entries)) {
            entries = [entries];
        }

        // Validate parameter
        if (entries.length === 0 || (entries.length === 1 && entries[0] === undefined)) {
            throw new Error('Missing or invalid `entries` parameter');
        }

        this.entries = [];
        this.msgDataCids = new Set();
        this.senderPubKeyHashes = new Map();
        this.receiverPubKeyHashes = new Map();

        for (let idx = 0, numEntries = entries.length; idx < numEntries; idx++) {
            const result = validateEntry(entries[idx]);
            let error;
            let strCid;

            if (!result.success) {
                error = result.error;
            }
            else if (this.msgDataCids.has(strCid = result.entry.msgDataCid.toString())) {
                error = 'duplicate `msgDataCid` property value';
            }

            if (error) {
                throw new Error(util.format('Invalid entry #%d: %s', idx + 1, error));
            }

            this.entries.push(result.entry);
            this.msgDataCids.add(strCid);
            addMapListItem(this.senderPubKeyHashes, result.entry.senderPubKeyHash.toString('base64'), idx);

            if (result.entry.receiverPubKeyHash) {
                addMapListItem(this.receiverPubKeyHashes, result.entry.receiverPubKeyHash.toString('base64'), idx);
            }
        }

        // Instantiate Merkle tree
        this.tree = merkle(this.entries.map(entry => conformLeafCid(entry.msgDataCid)), nodeHash);

        // Assemble batch document
        this.doc = {
            msgData: Array.from(this.msgDataCids),
            senders: Array.from(this.senderPubKeyHashes),
            receivers: Array.from(this.receiverPubKeyHashes),
            merkleRoot: this.merkleRoot.toString('base64')
        };
    }

    get merkleRoot() {
        return this.tree[this.tree.length - 1];
    }

    get hex() {
        if (this.buffer) {
            return this.buffer.toString('hex');
        }
    }

    get indicesEntryToCheckMessageData() {
        return this.entries.reduce((indices, entry, idx) => {
            if (!entry.msgData) {
                indices.push(idx)
            }

            return indices;
        }, []);
    }

    get isBuilt() {
        return !!this.buffer;
    }

    build() {
        if (!this.buffer) {
            const json = JSON.stringify(this.doc);

            this.buffer = zlib.gzipSync(Buffer.from(json));
        }
    }

    isAllMessageDataChecked() {
        return this.entries.every(entry => entry.msgData);
    }

    // Note: each listMsgData item (MessageEnvelope or MessageReceipt) should correspond to a batch document entry.
    //      Entries for which the message data has already been checked should have the corresponding item set to undefined
    checkMessageData(listMsgData) {
        if (!Array.isArray(listMsgData)) {
            listMsgData = [listMsgData];
        }

        const numEntries = this.entries.length;

        if (listMsgData.length !== numEntries) {
            throw new Error('Number of message data items do not match number of entries');
        }

        // Reset error
        this.listCheckMsgDataError = [];
        let hasError = false;

        for (let idx = 0; idx < numEntries; idx++) {
            const entry = this.entries[idx];
            const msgData = listMsgData[idx];
            let error;

            if (entry.msgData) {
                if (msgData !== undefined) {
                    error = 'Message data already checked for entry';
                }
            }
            else {
                error = checkMsgDataItem(msgData, entry);
            }

            if (error) {
                this.listCheckMsgDataError.push(error);
                hasError = true;
            }
            else {
                entry.msgData = msgData;
                this.listCheckMsgDataError.push(undefined);
            }
        }

        return !hasError;
    }

    isMessageDataInBatch(msgDataCid) {
        msgDataCid = Util.validateCid(msgDataCid);

        if (!msgDataCid) {
            throw new Error('Invalid message data (envelope or receipt) CID');
        }

        const proof = merkleProof(this.tree, conformLeafCid(msgDataCid));

        if (proof) {
            return merkleProof.verify(proof, nodeHash);
        }

        return false;
    }

    static fromBuffer(buf) {
        if (!Buffer.isBuffer(buf)) {
            throw new TypeError('Invalid argument type; expected Buffer');
        }

        // Try to decompress buffer
        let uncompressedBuf;

        try {
            uncompressedBuf = zlib.gunzipSync(buf);
        }
        catch (err) {
            throw new Error('Data is not compressed as expected');
        }

        // Try to parse JSON
        let json;

        try {
            json = JSON.parse(uncompressedBuf.toString());
        }
        catch (err) {}

        if (json === undefined || typeof json !== 'object' || json === null) {
            throw new Error('Data is not a valid JSON object');
        }

        // Check object structure
        if (!checkObjectProperties(json, {'msgData': 'array', 'senders': 'array', 'receivers': 'array', 'merkleRoot': 'string'})) {
            throw new Error('Invalid batch document object');
        }

        if (json.msgData.length === 0) {
            throw new Error('Invalid `msgData` property of batch document object');
        }

        let sendersPubKeyHashes;
        
        try {
            sendersPubKeyHashes = new Map(json.senders);
        }
        catch (err) {
            throw new Error('Invalid `senders` property of batch document object');
        }

        let receiversPubKeyHashes;

        try {
            receiversPubKeyHashes = new Map(json.receivers);
        }
        catch (err) {
            throw new Error('Invalid `receivers` property of batch document object');
        }
        
        // Assemble batch document entries
        const entries = json.msgData.map(msgData => {
            return {
                msgInfo: {},
                msgDataCid: msgData
            }
        });
        const numEntries = entries.length;

        // Add sender public key hashes
        for (let [hash, indices] of sendersPubKeyHashes) {
            if (!Array.isArray(indices)) {
                throw new Error('Invalid list of indices for sender');
            }

            indices.forEach(idx => {
                if (!Number.isInteger(idx) || idx < 0 || idx >= numEntries) {
                    throw new Error('Invalid index for sender');
                }

                const entry = entries[idx];

                if ('senderPubKeyHash' in entry.msgInfo) {
                    throw new Error('Duplicate sender for entry');
                }

                entry.msgInfo.senderPubKeyHash = hash;
            })
        }

        // Add receiver public key hashes
        for (let [hash, indices] of receiversPubKeyHashes) {
            if (!Array.isArray(indices)) {
                throw new Error('Invalid list of indices for receiver');
            }

            indices.forEach(idx => {
                if (!Number.isInteger(idx) || idx < 0 || idx >= numEntries) {
                    throw new Error('Invalid index for receiver');
                }

                const entry = entries[idx];

                if ('receiverPubKeyHash' in entry.msgInfo) {
                    throw new Error('Duplicate receiver for entry')
                }

                entry.msgInfo.receiverPubKeyHash = hash;
            })
        }

        let batchDoc;

        try {
            batchDoc = new BatchDocument(entries);
        }
        catch (err) {
            throw new Error('Invalid batch document entries');
        }

        if (batchDoc.merkleRoot.toString('base64') !== json.merkleRoot) {
            throw new Error('Inconsistent Merkle root hash in batch document');
        }

        // Everything is OK. Finalize batch document and return it
        batchDoc.buffer = buf;

        return batchDoc;
    }

    static fromHex(hex) {
        return BatchDocument.fromBuffer(Buffer.from(hex, 'hex'));
    }
}

function validateEntry(entry) {
    const result = {};
    const validatedEntry = {};
    const errors = [];

    if (typeof entry !== 'object' || entry === null) {
        errors.push('invalid entry type');
    }
    else {
        let msgInfoError = false;

        if (entry.msgInfo instanceof MessageEnvelope || entry.msgInfo instanceof MessageReceipt) {
            validatedEntry.msgData = entry.msgInfo;

            validatedEntry.senderPubKeyHash = validatedEntry.msgData.senderPubKeyHash;
            validatedEntry.receiverPubKeyHash = validatedEntry.msgData.receiverPubKeyHash;
        }
        else if (typeof entry.msgInfo !== 'object' || entry.msgInfo === null) {
            errors.push('missing or invalid `msgInfo` property');
            msgInfoError = true;
        }

        if (!validatedEntry.msgData && !msgInfoError) {
            validatedEntry.senderPubKeyHash = Util.validatePubKeyHash(entry.msgInfo.senderPubKeyHash);

            if (!validatedEntry.senderPubKeyHash) {
                errors.push('missing or invalid `msgInfo.senderPubKeyHash` property');
            }

            if ('receiverPubKeyHash' in entry.msgInfo) {
                validatedEntry.receiverPubKeyHash = Util.validatePubKeyHash(entry.msgInfo.receiverPubKeyHash);

                if (!validatedEntry.receiverPubKeyHash) {
                    errors.push('invalid `msgInfo.receiverPubKeyHash` property');
                }
            }
        }

        validatedEntry.msgDataCid = Util.validateCid(entry.msgDataCid);

        if (!validatedEntry.msgDataCid) {
            errors.push('missing or invalid `msgDataCid` property');
        }
        else if (validatedEntry.msgData && !multihashing.verify(validatedEntry.msgDataCid.multihash, validatedEntry.msgData.buffer)) {
            errors.push('inconsistent `msgDataCid` property: it does not match message data');
        }
    }

    if (errors.length > 0) {
        result.success = false;
        result.error = errors.join('; ');
    }
    else {
        result.success = true;
        result.entry = validatedEntry;
    }
    
    return result;
}

function addMapListItem(map, key, item) {
    if (!map.has(key)) {
        map.set(key, [item]);
    }
    else {
        map.get(key).push(item);
    }
}

function nodeHash(node) {
    return Buffer.concat([new Uint8Array([0x1]), bitcoinLib.crypto.hash256(node)]);
}

function conformLeafCid(cid) {
    return Buffer.concat([new Uint8Array([0x00]), cid.buffer]);
}

function checkMsgDataItem(msgData, entry) {
    let error;

    if (!(msgData instanceof MessageEnvelope || msgData instanceof MessageReceipt)) {
        error = 'Invalid message data: not an instance of MessageEnvelope nor MessageReceipt';
    }

    if (!error && (!msgData.senderPubKeyHash.equals(entry.senderPubKeyHash) || (entry.receiverPubKeyHash && !msgData.receiverPubKeyHash || !entry.receiverPubKeyHash && msgData.receiverPubKeyHash || msgData.receiverPubKeyHash && !msgData.receiverPubKeyHash.equals(entry.receiverPubKeyHash)))) {
        error = 'Invalid message data: it does not match sender and/or receiver';
    }

    if (!error && !multihashing.verify(entry.msgDataCid.multihash, msgData.buffer)) {
        error = 'Invalid message data: it does not match message data CID';
    }
    
    return error;
}

// Argument:
//  props (Object) A map where key is property name and value the expected property type
function checkObjectProperties(obj, props) {
    let keys;

    return (keys = Object.keys(obj)).length === Object.keys(props).length && keys.every(key => key in props && ((props[key] === 'array' && Array.isArray(obj[key])) || props[key] === typeof obj[key]));
}

module.exports = BatchDocument;