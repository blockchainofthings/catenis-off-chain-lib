// Catenis off-chain message data types
const msgDataType = Object.freeze({
    msgEnvelope: Object.freeze({
        name: 'msg-envelope',
        description: 'Off-Chain message envelope'
    }),
    msgReceipt: Object.freeze({
        name: 'msg-receipt',
        description: 'Off-Chain message receipt'
    })
});

module.exports = {
    msgDataType: msgDataType
};