const mongoose = require("mongoose");
try {
  mongoose.connect(
    "mongodb+srv://group02:123@se123.bg0yi.mongodb.net/ecommerce",
    {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useCreateIndex: true,
    }
  );
  console.log("Database Connected Successfully");
} catch (err) {
  console.log("Database Not Connected");
}
