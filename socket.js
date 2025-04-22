// server/socket.js
const socketIO = require("socket.io");

// Initialize Socket.IO with existing HTTP server
const initializeSocket = (server) => {
  const io = socketIO(server, {
    cors: {
      origin: "*", // In production, limit this to your client URL
      methods: ["GET", "POST"],
    },
  });

  // Store connected clients
  const clients = new Map();

  io.on("connection", (socket) => {
    console.log(`Client connected: ${socket.id}`);
    clients.set(socket.id, { socket });

    // Join a specific base room
    socket.on("joinBase", (baseId) => {
      socket.join(`base-${baseId}`);
      clients.get(socket.id).baseId = baseId;
    });

    // Leave a specific base room
    socket.on("leaveBase", (baseId) => {
      socket.leave(`base-${baseId}`);
      delete clients.get(socket.id).baseId;
    });

    // Handle disconnection
    socket.on("disconnect", () => {
      console.log(`Client disconnected: ${socket.id}`);
      clients.delete(socket.id);
    });
  });

  // Function to emit new entry to all clients or specific base
  const emitNewEntry = (entry, baseId = null) => {
    if (baseId) {
      // If baseId is provided, emit to specific base room
      io.to(`base-${baseId}`).emit("newEntry", entry);
    } else {
      // Otherwise, emit to all clients
      io.emit("newEntry", entry);
    }
  };

  return {
    io,
    emitNewEntry,
  };
};

module.exports = initializeSocket;