
'use strict';

angular.module('myApp',[])
	.controller('LoginController', function($scope,$http){

	$scope.email = '';
	$scope.password = '';
	$scope.message = 'Desconetado !!';
	
	$scope.submit = function () {
        $http.post("/auth/login", 
                      { email: $scope.email , password : $scope.password } )
	    .success(function (tokenWrapper) {
	      localStorage.token = tokenWrapper.token;
	      var encodedProfile = tokenWrapper.token.split('.')[1];
        $scope.message = 'Welcome ' + $scope.email + ' !!' 
	        
	    })
	    .error(function (error) {
	      alert(error);
		})
	}	

  $scope.whoiam = function () {
 		$http({
        	method: 'GET',
        	url: '/api/me',
            withCredentials: true, 
            headers: { 'content-type': 'application/x-www-form-urlencoded;'} })
      	.success(function (data) {
        	$scope.message = 'Conectado como: ' + data.email;
      	})
      	.error(function (error) {
          $scope.message = 'Usted no esta conectado';
        	alert(error);
      	});
  	};


	$scope.logout = function () {
    	$scope.message = 'Desconetado !!';
    	$scope.email = '';
    	$scope.password = '';
    	delete localStorage.token;
  	};

	
	})

	
	.factory('authInterceptor', function ($rootScope, $q) {
  		return {
    		request: function (config) {
      			config.headers = config.headers || {};
      		if (localStorage.token) {
        		config.headers.Authorization = 'Bearer ' + localStorage.token;
        		console.log("cesar probando token")
        		console.log(config.headers)
      		}
      		return config;
    	},
    	response: function (response) {
      	if (response.status === 401) {
        	alert('User not authenticated');
      	}
      	return response || $q.when(response);
    	}
  	};

	})

	.config(function ($httpProvider) {
  		$httpProvider.interceptors.push('authInterceptor');
	      // $httpProvider.defaults.useXDomain = true;
	      // $httpProvider.defaults.withCredentials = true;
	      // delete $httpProvider.defaults.headers.common['X-Requested-With'];
	});
