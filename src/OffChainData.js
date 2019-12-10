// Catenis off-chain data types
const offChainDataType = Object.freeze({
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
    type: offChainDataType
};