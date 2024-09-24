// Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.

'use strict';

(function () {
  function sfc32(a, b, c, d) {
    return function() {
      a |= 0; b |= 0; c |= 0; d |= 0;
      var t = (a + b | 0) + d | 0;
      d = d + 1 | 0;
      a = b ^ b >>> 9;
      b = c + (c << 3) | 0;
      c = (c << 21 | c >>> 11);
      c = c + t | 0;
      return (t >>> 0) / 4294967296;
    }
  };
  var seed = 1337 ^ 0xDEADBEEF;
  var rand = sfc32(0x9E3779B9, 0x243F6A88, 0xB7E15162, seed);
  // Mix initial states
  for (var i = 0; i < 15; i++) rand();
  Math.random = function() {
    return rand();
  };
  if (typeof(crypto) == 'object' &&
      typeof(crypto.getRandomValues) == 'function') {
    crypto.getRandomValues = function(arr) {
      var scale = Math.pow(256, arr.BYTES_PER_ELEMENT);
      for (var i = 0; i < arr.length; i++) {
        arr[i] = Math.floor(Math.random() * scale);
      }
      return arr;
    };
  }
})();
(function () {
  var date_count = 0;
  var date_count_threshold = 25;
  var orig_date = Date;
  // Time since epoch in milliseconds. This is replaced by script injector with
  // the date when the recording is done.
  var time_seed = {{WPR_TIME_SEED_TIMESTAMP}};
  Date = function() {
    if (this instanceof Date) {
      date_count++;
      if (date_count > date_count_threshold){
        time_seed += 50;
        date_count = 1;
      }
      switch (arguments.length) {
      case 0: return new orig_date(time_seed);
      case 1: return new orig_date(arguments[0]);
      default: return new orig_date(arguments[0], arguments[1],
        arguments.length >= 3 ? arguments[2] : 1,
        arguments.length >= 4 ? arguments[3] : 0,
        arguments.length >= 5 ? arguments[4] : 0,
        arguments.length >= 6 ? arguments[5] : 0,
        arguments.length >= 7 ? arguments[6] : 0);
      }
    }
    return new Date().toString();
  };
  Date.__proto__ = orig_date;
  Date.prototype = orig_date.prototype;
  Date.prototype.constructor = Date;
  orig_date.now = function() {
    return new Date().getTime();
  };
  orig_date.prototype.getTimezoneOffset = function() {
    var dst2010Start = 1268560800000;
    var dst2010End = 1289120400000;
    if (this.getTime() >= dst2010Start && this.getTime() < dst2010End)
      return 420;
    return 480;
  };
})();
