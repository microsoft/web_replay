// Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.

'use strict';

(function () {
  const originalFetch = window.fetch;

  window.fetch = function(...args) {
    if (args[0].endsWith("/graphql/v2")) {
      const variables = JSON.parse(args[1].body).variables;

      if (variables?.cursor) {
        let url = new URL(args[0]);
        url.searchParams.set("cursor", variables.cursor);

        args[0] = url;
      }
    }

    return originalFetch.apply(this, args);
  };
})();
