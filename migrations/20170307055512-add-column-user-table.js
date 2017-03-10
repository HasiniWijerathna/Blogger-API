'use strict';

module.exports = {
  up: function(queryInterface, Sequelize) {
      return queryInterface.addColumn('Users', 'userRole', Sequelize.INTEGER);
  },

  down: function(queryInterface, Sequelize) {
      return queryInterface.removeColumn('Users', 'userRole');
  },
};
