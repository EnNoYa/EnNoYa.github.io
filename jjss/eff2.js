  $(document).ready(function() {
     $("body").delay("200").fadeIn('1000');
    $("#nupic").click(function(event) {
      var mic = document.getElementById("mic"); 
      if(!mic.paused){
        mic.pause(); 
       document.getElementById("nupic").src="./pic/3686680582_c4e2a0c7fa01.png";}
       else{
       mic.play(); 
       document.getElementById("nupic").src="./pic/3686680582_c4e2a0c7fa.gif";}     
          });

     $("#am").click(function(event) {
      $("#pr").fadeOut('30');
      $("#li").fadeOut('30');
       $("#bio").delay("500").fadeIn('1000');
     });

     $("#op").click(function(event) {
      $("#pr").fadeOut('30');
      $("#bio").fadeOut('30');
       $("#li").delay("500").fadeIn('1000');
     });

     $("#im").click(function(event) {
      $("#bio").fadeOut('30');
      $("#li").fadeOut('30');
       $("#pr").delay("500").fadeIn('1000');
     });


      $("#pic1").click(function(){
        $("#pic2").fadeOut('fast');
        $("#pic3").fadeOut('fast');
        $("#pic1").delay(200).animate({width: "55vw"});
    });

      $("#pic1").mouseleave(function(){
        $("#pic2").delay(2000).fadeIn('fast');
        $("#pic3").delay(2000).fadeIn('fast');
        $("#pic1").delay(1500).animate({width: "150px"});
    });

 $("#pic2").click(function(){
        $("#pic1").fadeOut('30');
        $("#pic3").fadeOut('30');
        $("#pic2").delay(200).animate({width: "60vw"});
    });

      $("#pic2").mouseleave(function(){
        $("#pic1").delay(2000).fadeIn('30');
        $("#pic3").delay(2000).fadeIn('30');
        $("#pic2").delay(1500).animate({width: "150px"});
    });

       $("#pic3").click(function(){
        $("#pic2").fadeOut('30');
        $("#pic1").fadeOut('30');
        $("#pic3").delay(200).animate({width: "40vw"});
    });

      $("#pic3").mouseleave(function(){
        $("#pic2").delay(2000).fadeIn('30');
        $("#pic1").delay(2000).fadeIn('30');
        $("#pic3").delay(1500).animate({width: "150px"});
    });

  });
