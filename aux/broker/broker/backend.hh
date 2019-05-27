#ifndef BROKER_BACKEND_HH
#define BROKER_BACKEND_HH

namespace broker {

/// Describes the supported data store backend.
enum backend {
  memory,   ///< An in-memory backend based on a simple hash table.
  sqlite,   ///< A SQLite3 backend.
  rocksdb,  ///< A RocksDB backend.
};

} // namespace broker

#endif // BROKER_BACKEND_HH
