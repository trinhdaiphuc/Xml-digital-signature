$("#sign").submit(function (e) {
  e.preventDefault();
  const xml = document.getElementById("xml");
  const private = document.getElementById("private");
  const public = document.getElementById("public");
  const formData = new FormData();
  formData.append("xml", xml.files[0]);
  formData.append("private", private.files[0]);
  formData.append("public", public.files[0]);

  const url = `http://${window.location.host}/sign`;

  $.ajax({
    url: url,
    type: "POST",
    data: formData,
    success: function (data) {
      $("#sign-content").text(data);
    },
    processData: false,
    contentType: false,
  });
});

$("#copy").click(function (e) {
  e.preventDefault();
  $("#sign-content").select();
  document.execCommand("copy");
});

$("#verify").click(function (e) {
  e.preventDefault();
  const url = `http://${window.location.host}/verify`;
  const data = $("#verify-content").val();
  $.ajax({
    url: url,
    type: "POST",
    data: JSON.stringify({ data: data }),
    dataType: "json",
    contentType: "application/json; charset=utf-8",
    success: function (data) {
      alert(data);
    },
    error: function (e) {
      alert(e);
    },
  });
});
