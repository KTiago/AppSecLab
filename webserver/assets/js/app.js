var $ = require('jquery');
require('bootstrap');

$(document).ready(function() {
    setTimeout(function(){
        $(".alert").fadeOut(function() {
            $(this).remove();
        });
    }, 4000);
});
