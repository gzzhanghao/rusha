(function () {
  'use strict';

  var assert = require('assert');
  var asm = require('asm.js');
  var Rusha  = require('../rusha.min.js');

  function assertBytesEqual(buffer1, buffer2) {
    var v1 = new Int8Array(buffer1);
    var v2 = new Int8Array(buffer2);
    assert.strictEqual(v1.length, v2.length, 'Buffers do not have the same length');
    for (var i = 0; i < v1.length; i++) {
      assert.strictEqual(v1[i], v2[i], 'Item at ' + i + ' differs: ' + v1[i] + ' vs ' + v2[i]);
    }
  }

  var r = new Rusha();

  var abcArray = [97, 98, 99];
  var abcArrayBuffer = new Int8Array(abcArray).buffer;

  var abcHashedInt32Array = new Int32Array(new Int8Array([0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D]).buffer);

  describe('Rusha', function() {

    it('is valid asm.js', function() {
      assert(asm.validate(Rusha._core.toString()));
    });

    describe('digest', function() {
      it('returns hex string from ArrayBuffer', function() {
        assert.strictEqual(r.digest(abcArrayBuffer), 'a9993e364706816aba3e25717850c26c9cd0d89d');
      });
    });

    describe('digestFromArrayBuffer', function() {
      it('returns hex string from ArrayBuffer', function() {
        assert.strictEqual(r.digest(abcArrayBuffer), 'a9993e364706816aba3e25717850c26c9cd0d89d');
      });
    });

    describe('rawDigest', function() {
      it('returns Int32Array from ArrayBuffer', function() {
        assertBytesEqual(r.rawDigest(abcArrayBuffer), abcHashedInt32Array);
      });
    });
  });
})();
