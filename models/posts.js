'use strict';
module.exports = function(sequelize, DataTypes) {
  const Posts = sequelize.define('Posts', {
    title: DataTypes.STRING,
    content: DataTypes.STRING,
    BlogId: DataTypes.INTEGER
  }, {
    classMethods: {
      associate: function(models) {
        // associations can be defined here
        Posts.belongsTo(models.Blog);
        Posts.hasMany(models.Comments);
      }
    }
  });
  return Posts;
};
