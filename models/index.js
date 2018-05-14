const mongoose = require('mongoose');

module.exports.connect = (uri) => {
    // plug in the promise lib for mongoose
    mongoose.Promise = global.Promise;

    mongoose.connect(uri, {
        useMongoClient: true
    }).then(function(db) {

        require('./User');
        require('./Book');

    }).catch(function(err) {
        if (err) console.error(`Mongoose connectgion error: ${err}`);
        process.exit(1);
    });
}