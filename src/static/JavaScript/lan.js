// Sidebar javascript
//* Loop through all dropdown buttons to toggle between hiding and showing its dropdown content - This allows the user to have multiple dropdowns without any conflict */
let dropdown = document.getElementsByClassName("dropdown-btn");
let i;

for (i = 0; i < dropdown.length; i++) {
  dropdown[i].addEventListener("click", function() {
    this.classList.toggle("active");
    let dropdownContent = this.nextElementSibling;
    if (dropdownContent.style.display === "block") {
      dropdownContent.style.display = "none";
    } else {
      dropdownContent.style.display = "block";
    }
  });
}

//HIDE BUTTONS

const arp_btn = document.getElementById("arp-btn");
const syn_btn = document.getElementById("syn-btn");
const grab_btn = document.getElementById("grab-btn");

arp_btn.onclick = function () {

  document.getElementById("icmp-btn").style.visibility="hidden";
  document.getElementById("arp-btn").style.visibility="hidden";

};

syn_btn.onclick = function() {
      document.getElementById("syn-btn").style.visibility="hidden";

};

grab_btn.onclick = function () {
    document.getElementById("grab-btn").style.visibility = "hidden";

};

//ARP SCAN Jquery
$(document).ready(function () {
    $('#arp-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/resultsArp/",
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend(arp-btn) run!!');
            },
            success: function (data) {
                // message passed from views.py!
                alert(data.message);
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed ajax for arp-btn!');
            }
        });
    });
});

//ICMP SCAN JQuery
$(document).ready(function () {
    $('#icmp-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/resultsIcmp/",
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend for icmp-btn');
            },
            success: function (data) {
                // message passed from views.py!
                alert(data.message);
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Ajax completed for icmp-btn');
            }
        });
    });
});

//SYN-SCAN JQuery
$(document).ready(function () {
    $('#syn-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/resultsSyn/",
            beforeSend: () => {
                 $(".ajax_loader").show();
                 console.log('BeforeSend function(syn-btn) run');
            },
            success: function (data) {
                // message passed from views.py!
                alert(data.message);
            },
            complete: () => {
                 $(".ajax_loader").hide();
                console.log('Completed ajax for syn-btn!');
            }
        });
    });
});

//Banner-grab JQuery
$(document).ready(function () {
    $('#grab-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/resultsGrab/",
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend function(grab-btn) run!!');
            },
            success: function (data) {
                // message passed from views.py!
                alert(data.message);
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed ajax for grab-btn!');
            }
        });
    });
});

$(document).ready(function () {
    $('#cve-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/resultsCVEs/",
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend function(find-cves-btn) run!!');
            },
            success: function (data) {
                // message passed from views.py!
                alert(data.message);
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed ajax call');
            }
        });
    });
});

//Save-results JQuery
$(document).ready(function () {
    $('#save-btn').click(function () {
        $.ajax({
            type: "GET",
            url: "/dashboard/saveToDb/",
            beforeSend: () => {
                $(".ajax_loader").show();
                console.log('BeforeSend function(save-btn) run!!');
            },
            success: function (data) {
                // message passed from views.py!
                alert(data.message);
            },
            complete: () => {
                $(".ajax_loader").hide();
                console.log('Completed ajax for save-btn!');
            }
        });
    });
});




//csrf token
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        let cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            let cookie = cookies[i].trim();
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

let csrftoken = getCookie('csrftoken');

function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        }
    }
});