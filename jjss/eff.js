  jQuery.get('./testtext.txt', function(data) {
    alert(data);
     });
 
  $(document).ready(function() {

    $("button").click(function(event) {
      $("p").addClass('animated bounce').css("color","red");
      var pass=document.getElementById('pass').value;

      if(pass=="test"){
    $("h6").html("<a  href=./npp.html>test</a>");
    $("h6").css( "font-size","100px", "color", "gray");

      }
      else{pass="wrong";}
    });
    var count=0;
    $("p").mouseover(function(){
            
           var co;
    switch(count){
    case 0:co="red";
    break;
     case 1:co="orange";
     break;
     case 2:co="gray";
     break;
     case 3:co="green";
     break;
     case 4:co="blue";
     break;
     case 5:co="purple";
     break;
   }
    $(this).addClass('animated bounce').css("color",co);
     
    count++;
    count%=6;
 
    });
     $("#pic1").mouseenter(function(){
        $("#pic1").animate({width: "1000px"});
    });

      $("#pic1").mouseleave(function(){
        $("#pic1").delay(1500).animate({width: "100px"});
    });

 $("#pic2").mouseenter(function(){
        $("#pic2").animate({width: "1000px"});
    });

      $("#pic2").mouseleave(function(){
        $("#pic2").delay(1500).animate({width: "100px"});
    });

       $("#pic3").mouseenter(function(){
        $("#pic3").animate({width: "1000px"});
    });

      $("#pic3").mouseleave(function(){
        $("#pic3").delay(1500).animate({width: "100px"});
    });

  


  });

