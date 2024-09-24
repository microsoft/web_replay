// Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.

'use strict';

(function () {
  var inc = 0;

  console.time = function () {
    return;
  };

  console.timeEnd = function () {
    inc += 1000;
    return inc;
  };

  performance.now = function () {
    inc += 1000;
    return inc;
  };
})();
