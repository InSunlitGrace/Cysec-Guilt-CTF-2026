#!/bin/bash

PLAYLISTS=(
  "https://youtube.com/playlist?list=PLU2851hDb3SEesCjVCmseu60aJht1DQwh&si=9LsIFY9Z_w224ZHN"
  "https://www.youtube.com/playlist?list=PLU2851hDb3SE6S9YJFY6n1B4t_Qv26f1m"
  "https://www.youtube.com/playlist?list=PLU2851hDb3SGaiE8aNZrHgeO7AyR2Gtwd"
  "https://www.youtube.com/playlist?list=PLU2851hDb3SEbbc0Zx5KTD6-heWGGaKrb"
  "https://www.youtube.com/playlist?list=PLU2851hDb3SHWVA5voy8KB_Shz0Z3sxkm"
)

for pl in "${PLAYLISTS[@]}"; do
  echo "Downloading subs for: $pl"
  yt-dlp 
    --js-runtimes node \
    --skip-download \
    --write-auto-subs \
    --write-subs \
    --sub-langs "en.*" \
    --convert-subs srt \
    --cookies-from-browser firefox \
    -o "%(playlist_title)s/%(playlist_index)03d - %(title)s [%(id)s].%(ext)s" \
    "$pl"
done
