dockerfs_dirs:
- { name: "deluge/config" }
- { name: "nzbget/config" }
- { name: "nzbget/intermediate" }
- { name: "nzbhydra/config" }
- { name: "ombi/config" }
- { name: "radarr/config" }
- { name: "smokeping/config" }
- { name: "smokeping/data" }
- { name: "sonarr/config" }