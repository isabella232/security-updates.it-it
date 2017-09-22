---
TOCTitle: Elenchi revoche RMS
Title: Elenchi revoche RMS
ms:assetid: '688d4dfa-c928-4b2f-8116-2f9e87d2b6f7'
ms:contentKeyID: 18824628
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc720287(v=WS.10)'
---

Elenchi revoche RMS
===================

Gli elenchi di revoche specificano il contenuto, le applicazioni, gli utenti o altre entità che sono state revocate. Un'organizzazione potrebbe includere un'entità specificata in un elenco di revoche a causa di uno o più dei motivi seguenti:

-   Una chiave privata è compromessa oppure si ha il sospetto che lo sia.
-   Un proprietario ha richiesto la revoca di una chiave potenzialmente compromessa.
-   Un'entità non è più valida, ad esempio perché un dipendente è stato licenziato.
-   Esiste un difetto nel sistema di protezione, ad esempio un certificato rilasciato a un computer client è stato compromesso.
-   È necessario procedere a una ricertificazione a causa di modifiche delle autorizzazioni.
-   Le violazioni della protezione presenti in un'applicazione abilitata per RMS la rendono inadatta all'impiego per l'utilizzo di contenuto altamente riservato, così come per qualsiasi altro contenuto protetto.
-   Un contenuto in precedenza distribuito non è più aggiornato o appropriato per l'utilizzo.

Nella tabella seguente vengono elencate le entità che è possibile specificare in un elenco di revoche e le informazioni utilizzate per identificarle.

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Entità</th>
<th>Identificatore</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Gruppo di licenze o certificati</p></td>
<td style="border:1px solid black;"><p>ID o chiave pubblica dell'autorità emittente</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Gruppo di manifesti di applicazione</p></td>
<td style="border:1px solid black;"><p>ID o chiave pubblica dell'autorità emittente</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Licenza o certificato specifico</p></td>
<td style="border:1px solid black;"><p>ID o hash della licenza</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Manifesto di applicazione specifico</p></td>
<td style="border:1px solid black;"><p>ID o hash della licenza</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>Entità specifica</p></td>
<td style="border:1px solid black;"><p>ID o chiave pubblica dell'entità</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>Contenuto specifico</p></td>
<td style="border:1px solid black;"><p>ID del contenuto</p></td>
</tr>  
</tbody>  
</table>
  
| ![](images/Cc720287.note(WS.10).gif)Nota                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |  
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|  
| Per la revoca e l'esclusione, tutti gli hash sono SHA-1 \[NIS94c\], una versione aggiornata dell'algoritmo SHA (Secure Hash Algorithm), specificato in Secure Hash Standard (SHS, FIPS 180). SHA-1 è descritto nello standard ANSI X9.30 (parte 2). Per eseguire una revoca utilizzando il file manifesto dell'applicazione, è necessario estrarre l'ID e la chiave pubblica dell'emittente e l'ID o l'hash della licenza dal file manifesto dell'applicazione. Tuttavia, i manifesti dell'applicazione sono codificati su base 64, quindi le informazioni non vengono visualizzate in modo chiaro. Con Client SDK di Servizi Rights Management, è possibile utilizzare i metodi **DRMConstructCertificateChain**, **DRMDeconstructCertificateChain** e **DRMDecode** per sviluppare un programma che decodifichi il file manifesto dell'applicazione e ottenga le informazioni richieste. Per non consentire l'uso del contenuto protetto con RMS a determinate applicazioni, è possibile utilizzare la funzione di esclusione, grazie alla quale viene impedito al server RMS di concedere licenze d'uso a tali applicazioni. Il limite di questa funzione consiste nel non poter evitare la decrittografia del contenuto protetto con RMS da parte di utenti con licenze d'uso valide. Per ulteriori informazioni sull'esclusione delle applicazioni, vedere Esclusione di applicazioni in "Gestione di un server RMS" in questa documentazione. |
  
Gli elenchi di revoche sono file XrML che specificano i parametri indicati nella tabella seguente.
  
###  

<p> </p>
<table style="border:1px solid black;">  
<colgroup>  
<col width="50%" />  
<col width="50%" />  
</colgroup>  
<thead>  
<tr class="header">  
<th>Parametro</th>  
<th>Descrizione</th>  
</tr>  
</thead>  
<tbody>  
<tr class="odd">
<td style="border:1px solid black;"><p>ISSUEDTIME</p></td>
<td style="border:1px solid black;"><p>L'ora di sistema a cui il file XrML è stato creato. Viene impiegata dalla condizione REFRESH presente nella licenza d'uso al fine di stabilire l'età dell'elenco di revoche.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>ISSUER</p></td>
<td style="border:1px solid black;"><p>Il nome, l'ID e l'indirizzo dell'autorità emittente dell'elenco di revoche.</p></td>
</tr>  
<tr class="odd">
<td style="border:1px solid black;"><p>PUBLICKEY</p></td>
<td style="border:1px solid black;"><p>La chiave pubblica dell'autorità emittente dell'elenco di revoche.</p></td>
</tr>  
<tr class="even">
<td style="border:1px solid black;"><p>REVOCATIONLIST</p></td>
<td style="border:1px solid black;"><p>Il nome, il tipo e l'ID di tutte le entità revocate.</p></td>
</tr>  
</tbody>  
</table>
