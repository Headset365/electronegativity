angular.module('app').controller('Ctrl', function ($scope, $sce, $compile, $interpolate, $http) {
  // dynamic markup trusted or compiled: flagged
  $scope.trusted = $sce.trustAsHtml($scope.userInput);
  $scope.alsoTrusted = $sce.trustAs($sce.HTML, $scope.commentBody);
  $compile($scope.serverTemplate)($scope);
  $scope.rendered = $interpolate($scope.expr)($scope);

  // safe: constant markup, or a non-HTML trust context
  $scope.staticTrusted = $sce.trustAsHtml('<b>welcome</b>');
  $scope.resourceUrl = $sce.trustAsResourceUrl($scope.url);
  $compile('<b>static</b>')($scope);
});
