// Copyright (c) Microsoft Corporation.
// Licensed under the BSD-3-Clause license.

'use strict';

(function () {
  var inc = 0;

  console.time = function () {
    return;
  };

  console.timeEnd = function () {
    inc += 0.001;
    return inc;
  };

  var totalVideoFrames = 0;

  HTMLVideoElement.prototype.getVideoPlaybackQuality = function() {
    totalVideoFrames += 100;

    return {
      creationTime: 0,
      droppedVideoFrames: 0,
      totalVideoFrames: totalVideoFrames,
    };
  };

  document.addEventListener("DOMContentLoaded", function() {
    var videos = document.getElementsByTagName("video");
    var video = videos[videos.length - 1];

    function playEventListener() {
      video.autoplay = false;
      video.pause();
    }

    video.addEventListener("play", playEventListener);

    video.autoplay = false;
    video.pause();

    var numClicked = 0;
    var totalClicks = 3;
    var videoStartTime = 0;
    var title = "TOS";

    function clickEventListener() {
      numClicked++;

      if (numClicked === 1) {
        disableAmbientMode();
      }

      if (numClicked === totalClicks) {
        video.removeEventListener("play", playEventListener);
        document.removeEventListener("click", clickEventListener);

        var urlParams = new URLSearchParams(window.location.search);

        if (urlParams.get("v") === "yfj8zYFU-Tc") {
          videoStartTime = 30;
          title = "NASA";
        }

        video.currentTime = videoStartTime;

        setTimeout(function () {
          video.autoplay = true;
          video.play();
        }, 2000);
      }
    }

    document.addEventListener("keydown", function (e) {
      if (e.key !== "k") {
        return;
      }

      var body = JSON.stringify({
        from: "youtube",
        content: {
          url: window.location.href,
          title,
          start: videoStartTime,
          end: video.currentTime
        }
      });

      fetch(`${window.location.origin}/web-page-replay-record-log`, {
        method: "POST",
        body
      });
    });

    document.addEventListener("click", clickEventListener);
  }, { once: true });
})();
