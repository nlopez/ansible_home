dockerfs_dirs:
- { name: "plexpy/config" }
- { name: "pms/config" }
- { name: "pms/transcode" }
- { name: "nextcloud/config" }
- { name: "nextcloud-mariadb/config" }
