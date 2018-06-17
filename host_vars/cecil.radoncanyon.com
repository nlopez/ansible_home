dockerfs_dirs:
- { name: "prometheus/data" }
- { name: "prometheus/config" }
