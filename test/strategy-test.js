var vows = require('vows');
var assert = require('assert');
var util = require('util');
var DeskcomStrategy = require('passport-deskcom/strategy');

vows.describe('DeskcomStrategy').addBatch({
  'strategy': {
    topic: function() {
      return new DeskcomStrategy({
        consumerKey: 'desk-com-test-key',
        consumerSecret: 'desk-com-test-secret',
        site: 'https://example.desk.com/'
      },
      function() {});
    },

    'should be name deskcom' : function (strategy) {
      assert.equal(strategy.name, 'deskcom');
    }

  }
}).export(module);
