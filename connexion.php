<?php 
    session_start(); // Démarrage de la session:permet de stocker des informations pour un utilisateur pour un temps donné
    require_once 'config.php'; // On inclut la connexion à la base de données

    if(!empty($_POST['email']) && !empty($_POST['password'])) // Si il existe les champs email, password et qu'il sont pas vident
    {
        // pour eviter la faille XSS(permettant d'introduire du script  malveillant dans un site pour attaquer les utilisateurs)
        $email = htmlspecialchars($_POST['email']); 
        $password = htmlspecialchars($_POST['password']);
        
        $email = strtolower($email); // email transformé en minuscule
        
        // On regarde si l'utilisateur est inscrit dans la table utilisateurs
        $check = $bdd->prepare('SELECT pseudo, email, password FROM users WHERE email = ?');
        $check->execute(array($email));//on met la reponse de la requette dans un tableau
        $data = $check->fetch();//stocke les donnees dans data et on recherche avec fetch
        $row = $check->rowCount();//verifier si le user exite dans la table ou pas 
        
        

        // Si > à 0 alors l'utilisateur existe
        if($row > 0)
        {
            // Si le mail est bon niveau format
            if(filter_var($email, FILTER_VALIDATE_EMAIL))
            {
                // Si le mot de passe est le bon
                $password = hash('audrey16', $password);
                if($data['password'] === $password)//triple egale parceque quand on utilse le hash il y a une faille de securité avec le double egale
                {
                    // On créer la session et on redirige sur landing.php
                    $_SESSION['users'] = $data['pseudo'];
                    header('Loyaltycard: landing.php');
                    die();
                }else{ header('Loyaltycard: index.php?login_err=password'); die(); }
            }else{ header('Loyaltycard: index.php?login_err=email'); die(); }
        }else{ header('Loyaltycard: index.php?login_err=already'); die(); }
    }else{ header('Loyaltycard: index.php'); die();} // si le formulaire est envoyé sans aucune données