const util = require('util');
const zlib = require('zlib');
const bitcoinLib = require('bitcoinjs-lib');
const merkle = require('merkle-lib');
const merkleProof = require('merkle-lib/proof');
const MessageEnvelope = require('./MessageEnvelope');
const MessageReceipt = require('./MessageReceipt');
const Util = require('./Util');

const initialVersion = 0;
const latestVersion = 1;
const hashFunctions = [
    // Initial version (ver. 0)
    {
        leaf(node) {
            return Buffer.concat([Buffer.from([0x00]), node]);
        },
        internalNode(node) {
            return Buffer.concat([Buffer.from([0x01]), bitcoinLib.crypto.hash256(node)]);
        }
    },
    // Version 1
    {
        leaf(node) {
            return bitcoinLib.crypto.sha256(Buffer.concat([Buffer.from([0x00]), node]));
        },
        internalNode(node) {
            return bitcoinLib.crypto.sha256(Buffer.concat([Buffer.from([0x01]), node]));
        }
    }
];

class BatchDocument {
    /**
     * Class constructor
     * @param {[Object]} entries An array of objects containing information describing the message data (either message envelopes or message receipts)
     *                            to be included in the batch, with the following properties:
     *                            - msgInfo (MessageEnvelope|MessageReceipt|Object) Information about the message the message envelope or receipt of which is to be added to the batch.
     *                                Can be either an instance of MessageEnvelope, and instance of MessageReceipt or a literal object with the following properties:
     *                                - senderPubKeyHash (String|Buffer) The public key hash of the Catenis device that sent the message
     *                                - receiverPubKeyHash (String|Buffer) (optional) The public key hash of the Catenis device to which the message was sent
     *                            - msgDataCid (String|Buffer|CID) The IPFS CID of the message envelope or receipt to add to the batch
     * @param {Number} [version] Version of batch document data structure to use
     */
    constructor(entries, version = latestVersion) {
        if (!Array.isArray(entries)) {
            entries = [entries];
        }

        // Validate parameter
        if (entries.length === 0 || (entries.length === 1 && entries[0] === undefined)) {
            throw new Error('Missing or invalid `entries` parameter');
        }

        if (!isValidVersion(version)) {
            throw new Error('Invalid `version` parameter');
        }

        this.entries = [];
        this.version = version;
        this.setMsgDataCids = new Set();
        this.mapSenderPubKeyHashes = new Map();
        this.mapReceiverPubKeyHashes = new Map();

        for (let idx = 0, numEntries = entries.length; idx < numEntries; idx++) {
            const result = validateEntry(entries[idx]);
            let error;
            let strCid;

            if (!result.success) {
                error = result.error;
            }
            else if (this.setMsgDataCids.has(strCid = result.entry.msgDataCid.toString())) {
                error = 'duplicate `msgDataCid` property value';
            }

            if (error) {
                throw new Error(util.format('Invalid entry #%d: %s', idx + 1, error));
            }

            this.entries.push(result.entry);
            this.setMsgDataCids.add(strCid);
            addMapListItem(this.mapSenderPubKeyHashes, result.entry.senderPubKeyHash.toString('base64'), idx);

            if (result.entry.receiverPubKeyHash) {
                addMapListItem(this.mapReceiverPubKeyHashes, result.entry.receiverPubKeyHash.toString('base64'), idx);
            }
        }

        this.msgDataCids = Array.from(this.setMsgDataCids);

        // Instantiate Merkle tree
        this.hashFunction = hashFunctions[this.version];
        this.tree = merkle(this.entries.map(entry => this.hashFunction.leaf(entry.msgDataCid.buffer)), this.hashFunction.internalNode);

        // Assemble batch document
        this.doc = {
            version: this.version,
            msgData: this.msgDataCids,
            senders: Array.from(this.mapSenderPubKeyHashes),
            receivers: Array.from(this.mapReceiverPubKeyHashes),
            merkleRoot: this.merkleRoot.toString('base64')
        };

        if (version === initialVersion) {
            delete this.doc.version;
        }
    }

    get merkleRoot() {
        return this.tree[this.tree.length - 1];
    }

    get hex() {
        if (this.buffer) {
            return this.buffer.toString('hex');
        }
    }

    get base64() {
        if (this.buffer) {
            return this.buffer.toString('base64');
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

        const proof = merkleProof(this.tree, this.hashFunction.leaf(msgDataCid.buffer));

        if (proof) {
            return merkleProof.verify(proof, this.hashFunction.internalNode);
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
        if (!checkObjectProperties(json, {
            'version?': 'number',
            msgData: 'array',
            senders: 'array',
            receivers: 'array',
            merkleRoot: 'string'
        })) {
            throw new Error('Invalid batch document object');
        }

        let version;

        if ('version' in json) {
            if (!isValidVersion(json.version) || json.version === initialVersion) {
                throw new Error('Invalid `version` property of batch document object');
            }

            version = json.version;
        }
        else {
            // No version property present. Set version as initial version
            version = initialVersion;
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
            batchDoc = new BatchDocument(entries, version);
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

    static fromBase64(base64) {
        return BatchDocument.fromBuffer(Buffer.from(base64, 'base64'));
    }
}

function isValidVersion(n) {
    return Number.isInteger(n) && n >= initialVersion && n <= latestVersion;
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

function checkMsgDataItem(msgData, entry) {
    let error;

    if (!(msgData instanceof MessageEnvelope || msgData instanceof MessageReceipt)) {
        error = 'Invalid message data: not an instance of MessageEnvelope nor MessageReceipt';
    }

    if (!error && (!msgData.senderPubKeyHash.equals(entry.senderPubKeyHash) || (entry.receiverPubKeyHash && !msgData.receiverPubKeyHash || !entry.receiverPubKeyHash && msgData.receiverPubKeyHash || msgData.receiverPubKeyHash && !msgData.receiverPubKeyHash.equals(entry.receiverPubKeyHash)))) {
        error = 'Invalid message data: it does not match sender and/or receiver';
    }

    return error;
}

// Argument:
//  props (Object) A map where key is property name and value the expected property type
function checkObjectProperties(obj, props) {
    let requiredPropsFound = 0;

    let error = Object.keys(obj).some(key => {
        let prop = key;

        if ((prop in props) || ((prop += '?') in props)) {
            if (!((props[prop] === 'array' && Array.isArray(obj[key])) || props[prop] === typeof obj[key])) {
                // Key has an unexpected type.
                //  Stop iteration indicating failure
                return true;
            }

            // Check if it is not an optional property
            if (!prop.endsWith('?')) {
                requiredPropsFound++;
            }

            return false;
        }
        else {
            // Key is not one of the expected props.
            //  Stop iteration indicating failure
            return true;
        }
    });

    if (!error) {
        const totalRequiredProps = Object.keys(props).reduce((count, prop) => {
            if (!prop.endsWith('?')) {
                count++;
            }

            return count;
        }, 0);

        error = requiredPropsFound !== totalRequiredProps;
    }

    return !error;
}

module.exports = BatchDocument;