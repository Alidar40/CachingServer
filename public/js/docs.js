$(function() {
    $( document ).ready(function() {
        login = getCookie("login")
        var users;

        $.ajax({
            url: "/api/users",
            type: 'GET',
            dataType: "json",
            success: function(resp){
                users = resp.response.users;
                for(i = 0; i < users.length; i++){
                    $("#grant-user").append("<option value=\"" + users[i] + "\">" + users[i] + "</option>");
                }
            }
        });

        $.ajax({
            url: "/api/docs",
            type: 'GET',
            dataType: "json",
            success: function(resp){
                var docs = resp.data.docs;
                var index;
                var author;
                var grant;
                for(i = 0; i < docs.length; i++){
                    if (login === docs[i].author) {
                        author = "You"
                        $("#grant-file").append("<option value=\"" + docs[i].id + "\">" + docs[i].name+ "</option>");
                        $("#delete-file").append("<option value=\"" + docs[i].id + "\">" + docs[i].name+ "</option>");
                        if (docs[i].grant !== null){
                            if (docs[i].grant.length > 1) {
                               $("#cancelperm-file").append("<option value=\"" + docs[i].id + "\">" + docs[i].name+ "</option>"); 
                                for(j = 0; j < docs[i].grant.length; j++){
                                    for(k = 0; k < users.length; k++){
                                        if(docs[i].grant[j] === users[k]){
                                            $("#cancelperm-user").append("<option value=\"" + users[k] + "\">" + users[k]+ "</option>"); 
                                            continue
                                        }
                                    }
                                }
                            }
                        }

                    } else {
                        author = docs[i].author
                    }
                    if (docs[i].grant === null) {
                        grant = "Only You"
                    } else {
                        grant = docs[i].grant
                    }

                    if (docs[i].public === true) {
                        $("#private-file").append("<option value=\"" + docs[i].id + "\">" + docs[i].name+ "</option>");
                    } else {
                        $("#public-file").append("<option value=\"" + docs[i].id + "\">" + docs[i].name+ "</option>");
                    }

                    $("#docs-table").append("<tr><td>" + "<a href=\"/api/docs/"+docs[i].id+"\">"+docs[i].name+"</a>" + "</td>" +
                        "<td>" + docs[i].public + "</td>" + 
                        "<td>" + docs[i].created + "</td>" +
                        "<td>" + author + "</td>" +
                        "<td>" + grant + "</td>" +"</tr>");
                }
            }
        });

        
    });
});


$("#file-button").click(function(e) {
    e.preventDefault();

    $.ajax({
        url: '/api/docs',
        type: 'POST',
    
        data: new FormData($('#file-form')[0]),
        
        enctype: 'multipart/form-data',
        cache: false,
        contentType: false,
        processData: false,

        success: function(){
            location.reload();
        }
    });
});

$(':file').on('change', function() {
    var file = this.files[0];
    if (file.size > 16777216) {
        alert('max upload size is 16Mb')
    }
});


function handleDeleteClick(){
    var selectFile = document.getElementById("delete-file");
    var fileId = selectFile.options[selectFile.selectedIndex].value;

    $.ajax({
        url: "/api/docs/"+fileId,
        type: 'DELETE',
        success: function(){
            location.reload();
        }
    });
};

function handleGrantClick(){
    var selectFile = document.getElementById("grant-file");
    var fileId = selectFile.options[selectFile.selectedIndex].value;

    var selectUser = document.getElementById("grant-user");
    var user = selectUser.options[selectUser.selectedIndex].value;
    $.ajax({
        url: "/api/grant?login="+user+"&docid="+fileId,
        type: 'POST',
        dataType: "json",
        success: function(){
            location.reload();
        }
    });
};

function handleCancelClick(){
    var selectFile = document.getElementById("cancelperm-file");
    var fileId = selectFile.options[selectFile.selectedIndex].value;

    var selectUser = document.getElementById("cancelperm-user");
    var user = selectUser.options[selectUser.selectedIndex].value;
    $.ajax({
        url: "/api/grant?login="+user+"&docid="+fileId,
        type: 'DELETE',
        dataType: "json",
        success: function(){
            location.reload();
        }
    });
};

function handlePublicClick(){
    var selectFile = document.getElementById("public-file");
    var fileId = selectFile.options[selectFile.selectedIndex].value;
    $.ajax({
        url: "/api/grant/public/"+fileId,
        type: 'POST',
        dataType: "json",
        success: function(){
            location.reload();
        }
    });
};

function handlePrivateClick(){
    var selectFile = document.getElementById("private-file");
    var fileId = selectFile.options[selectFile.selectedIndex].value;
    $.ajax({
        url: "/api/grant/private/"+fileId,
        type: 'POST',
        dataType: "json",
        success: function(){
            location.reload();
        }
    });
};

function handleLogoutClick(){
    $.ajax({
        url: "/api/auth/",
        type: 'DELETE',
        success: function(){
            location.reload();
        }
    });
};
