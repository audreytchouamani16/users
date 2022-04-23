<?php 
    require_once 'config.php'; // On inclu la connexion à la bdd

    // Si les variables existent et qu'elles ne sont pas vides
    if(!empty($_POST['pseudo']) && !empty($_POST['email']) && !empty($_POST['password']) && !empty($_POST['password_retype']))
    {
        //  pour eviter la faille XSS(permettant d'introduire du script  malveillant dans un site pour attaquer les utilisateurs)
        $pseudo = htmlspecialchars($_POST['pseudo']);
        $email = htmlspecialchars($_POST['email']);
        $password = htmlspecialchars($_POST['password']);
        $password_retype = htmlspecialchars($_POST['password_retype']);

        // On vérifie si l'utilisateur existe
        $check = $bdd->prepare('SELECT pseudo, email, password FROM users WHERE email = ?');
        $check->execute(array($email));//on met la reponse de la requette dans un tableau
        $data = $check->fetch();//stocke les donnees dans data et on recherche avec fetch
        $row = $check->rowCount();//verifier si le user exite dans la table ou pas 

        $email = strtolower($email); // on transforme toute les lettres majuscule en minuscule pour éviter que Foo@gmail.com et foo@gmail.com soient deux compte différents ..
        
        // Si la requete renvoie un 0 alors l'utilisateur n'existe pas 
        if($row == 0){ 
            if(strlen($pseudo) <= 100){ // On verifie que la longueur du pseudo <= 100
                if(strlen($email) <= 100){ // On verifie que la longueur du mail <= 100
                    if(filter_var($email, FILTER_VALIDATE_EMAIL)){ // Si l'email est de la bonne forme
                        if($password === $password_retype){ // si les deux mdp saisis sont bon

                            
                            // On insère dans la base de données
                            $insert = $bdd->prepare('INSERT INTO users(pseudo, email, password ) VALUES(:pseudo, :email, :password)');
                            $insert->execute(array(
                                'pseudo' => $pseudo,
                                'email' => $email,
                                'password' => $password,
                            ));
                            // On redirige avec le message de succès
                            header('Locyaltycard:inscription.php?reg_err=success');
                            die();
                        }else{ header('Loyaltycard: inscription.php?reg_err=password'); die();}//die permet d'afficher un message et de quitter le script
                    }else{ header('Loyaltycard: inscription.php?reg_err=email'); die();}
                }else{ header('Loyaltycard: inscription.php?reg_err=email_length'); die();}
            }else{ header('Loyaltycard: inscription.php?reg_err=pseudo_length'); die();}
        }else{ header('Loyaltycard: inscription.php?reg_err=already'); die();}
    }