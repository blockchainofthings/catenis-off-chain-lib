const expect = require('chai').expect;
const Util = require('../src/Util');

describe('Write 64-bit numbers to buffer', function () {
    const buf64 = Buffer.alloc(8);

    it('should correctly write small numbers (< 32 bits)', function () {
        Util.writeInt64BE(12345, buf64, 0);

        expect(buf64.equals(Buffer.from('0000000000003039', 'hex'))).to.be.true;
    });

    it('should correctly write large numbers (> 32 bits)', function () {
        Util.writeInt64BE(6336313684422, buf64, 0);

        expect(buf64.equals(Buffer.from('000005c349b9f1c6', 'hex'))).to.be.true;
    });

    it('should correctly write small negative numbers (< 32 bits)', function () {
        Util.writeInt64BE(-12345, buf64, 0);

        expect(buf64.equals(Buffer.from('ffffffffffffcfc7', 'hex'))).to.be.true;
    });

    it('should correctly write large negative numbers (> 32 bits)', function () {
        Util.writeInt64BE(-6336313684422, buf64, 0);

        expect(buf64.equals(Buffer.from('fffffa3cb6460e3a', 'hex'))).to.be.true;
    });

    it('should correctly write negative numbers multiple of 2 to the power of 32 (> 32 bits)', function () {
        Util.writeInt64BE(-1408070668255232, buf64, 0);

        expect(buf64.equals(Buffer.from('fffaff5e00000000', 'hex'))).to.be.true;
    });
});

describe('Read 64-bit numbers from buffer', function () {
    const buf64 = Buffer.alloc(8);

    it('should correctly read small numbers (< 32 bits)', function () {
        Buffer.from('0000000000003039', 'hex').copy(buf64);

        expect(Util.readInt64BE(buf64, 0)).to.equal(12345);
    });

    it('should correctly read large numbers (> 32 bits)', function () {
        Buffer.from('000005c349b9f1c6', 'hex').copy(buf64);

        expect(Util.readInt64BE(buf64, 0)).to.equal(6336313684422);
    });

    it('should correctly read small negative numbers (< 32 bits)', function () {
        Buffer.from('ffffffffffffcfc7', 'hex').copy(buf64);

        expect(Util.readInt64BE(buf64, 0)).to.equal(-12345);
    });

    it('should correctly read large negative numbers (> 32 bits)', function () {
        Buffer.from('fffffa3cb6460e3a', 'hex').copy(buf64);

        expect(Util.readInt64BE(buf64, 0)).to.equal(-6336313684422);
    });

    it('should correctly write negative numbers multiple of 2 to the power of 32 (> 32 bits)', function () {
        Buffer.from('fffaff5e00000000', 'hex').copy(buf64);

        expect(Util.readInt64BE(buf64, 0)).to.equal(-1408070668255232);
    });
});
