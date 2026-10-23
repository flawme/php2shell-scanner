<?php
if (!empty($_FILES["avatar"])) {
    move_uploaded_file(
        $_FILES["avatar"]["tmp_name"],
        "/srv/uploads/" . basename($_FILES["avatar"]["name"])
    );
}
