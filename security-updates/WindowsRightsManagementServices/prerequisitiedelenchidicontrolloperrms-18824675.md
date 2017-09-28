---
TOCTitle: Prerequisiti ed elenchi di controllo per RMS
Title: Prerequisiti ed elenchi di controllo per RMS
ms:assetid: '836d96ef-d0fd-4935-b595-e8dec19cbb2b'
ms:contentKeyID: 18824675
ms:mtpsurl: 'https://technet.microsoft.com/it-it/library/Cc747582(v=WS.10)'
---

Prerequisiti ed elenchi di controllo per RMS
============================================

Prima di iniziare a installare RMS, esaminare i prerequisiti tecnologici per l'utilizzo di RMS, poiché ciascuna delle tecnologie elencate è integrata con RMS e la loro comprensione di base è importante per distribuire con successo RMS. L'utilizzo dei seguenti elenchi di controllo è di aiuto per creare elenchi di attività e piani di distribuzione e amministrazione di RMS:

-   [Prerequisiti tecnologici](#bkmk_9)
-   [Elenchi di controllo per la distribuzione di RMS](#bkmk_10)
-   [Elenchi di controllo per l'amministrazione di RMS](#bkmk_14)

<span id="BKMK_9"></span>
Prerequisiti tecnologici
------------------------

Questa documentazione fornisce informazioni che aiutano a capire come funziona Windows RMS, come pianificare ed eseguire una distribuzione nella propria organizzazione e come gestire il sistema giorno per giorno. Si presuppone una conoscenza degli argomenti seguenti:

-   Distribuzione e amministrazione di Windows Server 2003
-   Distribuzione e amministrazione di Active Directory
-   Distribuzione e amministrazione di Microsoft® Internet Information Services 6.0 (IIS)
-   Amministrazione di Microsoft® SQL Server™ 2000
-   Concetti di base sull'infrastruttura a chiave pubblica (PKI, Public Key Infrastructure)
-   Protezione e utilizzo in rete dei server

Per ulteriori informazioni su questi argomenti, vedere “Risorse aggiuntive” in [Utilizzo di un server RMS](http://go.microsoft.com/fwlink/?linkid=42495), in questa documentazione.

<span id="BKMK_10"></span>
Elenchi di controllo per la distribuzione di RMS
------------------------------------------------

Questa sezione fornisce elenchi di controllo per le seguenti attività di distribuzione:

-   [Distribuzione di un'installazione con un singolo server](#bkmk_11)
-   [Distribuzione di cluster di certificazione principali e di gestione licenze](#bkmk_12)
-   [Distribuzione di RMS negli insiemi di strutture](#bkmk_13)

Per ulteriori informazioni sulla distribuzione di RMS, vedere [Distribuzione di un sistema RMS](http://go.microsoft.com/fwlink/?linkid=42494) in questa documentazione.

<span id="BKMK_11"></span>
Distribuzione di un'installazione con un singolo server
-------------------------------------------------------

Utilizzare il seguente elenco di controllo per distribuire un singolo server RMS.

###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Passaggio</th>
<th>Riferimento</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Rivedere informazioni concettuali e di pianificazione.</p></td>
<td style="border:1px solid black;"><p>&quot;Preparazione di una distribuzione di RMS&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Verificare i requisiti di sistema e assicurarsi che l'hardware e il software necessari siano disponibili.</p></td>
<td style="border:1px solid black;"><p>&quot;Prerequisiti di infrastruttura per RMS&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=37537">Pianificazione di una distribuzione di RMS</a>.</p>
<p>&quot;Pianificazione dell'infrastruttura del server di database&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=37537">Pianificazione di una distribuzione di RMS</a>.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Configurare l'infrastruttura, inclusi i prerequisiti hardware e software, gli account amministrativi e il supporto per SMS o per i criteri di gruppo, in base alle necessità.</p></td>
<td style="border:1px solid black;"><p>&quot;Preparazione di una distribuzione RMS&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Installare e configurare RMS sul server.</p></td>
<td style="border:1px solid black;"><p>&quot;Configurazione dei servizi di certificazione e gestione licenze sul primo server&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Eseguire il test della distribuzione.</p></td>
<td style="border:1px solid black;"><p>&quot;Impostazione di un ambiente di test&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Implementare RMS nell'ambiente di produzione.</p></td>
<td style="border:1px solid black;"><p>&quot;Definizione dell'ambito dell'implementazione di RMS&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
</tbody>
</table>
  
<span id="BKMK_12"></span>
Distribuzione di cluster di certificazione principali e di gestione licenze  
---------------------------------------------------------------------------
  
Utilizzare il seguente elenco di controllo per distribuire cluster di certificazione principali e di gestione licenze.
  
###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Passaggio</th>
<th>Riferimento</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Rivedere informazioni concettuali e di pianificazione.</p></td>
<td style="border:1px solid black;"><p>&quot;Preparazione di una distribuzione RMS&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Verificare i requisiti di sistema e assicurarsi che l'hardware e il software necessari siano disponibili.</p></td>
<td style="border:1px solid black;"><p>&quot;Prerequisiti di infrastruttura per RMS&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=37537">Pianificazione di una distribuzione di RMS</a>.</p>
<p>&quot;Pianificazione dell'infrastruttura di server database&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=37537">Pianificazione di una distribuzione di RMS</a>.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Rivedere il piano di distribuzione per definire la topologia e i componenti da installare.</p></td>
<td style="border:1px solid black;"><p>&quot;Determinazione della topologia RMS&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=37537">Pianificazione di una distribuzione di RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Configurare l'infrastruttura, inclusi i prerequisiti hardware e software, gli account amministrativi e il supporto per SMS o per i criteri di gruppo, in base alle necessità.</p></td>
<td style="border:1px solid black;"><p>&quot;Preparazione di una distribuzione RMS&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Installare e configurare RMS sui server del cluster di certificazione principale.</p></td>
<td style="border:1px solid black;"><p>&quot;Configurazione dei servizi di certificazione e gestione licenze sul primo server&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p>
<p>&quot;Aggiunta di server per supportare la certificazione e la gestione delle licenze&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Installare e configurare RMS sui server del cluster di gestione licenze.</p></td>
<td style="border:1px solid black;"><p>&quot;Configurazione dei servizi di certificazione e gestione licenze sul primo server&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p>
<p>&quot;Aggiunta di server per supportare la certificazione e la gestione delle licenze&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Configurare il bilanciamento del carico.</p></td>
<td style="border:1px solid black;"><p>&quot;Espansione dell'infrastruttura di base per supportare il clustering&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Eseguire il test della distribuzione.</p></td>
<td style="border:1px solid black;"><p>&quot;Impostazione di un ambiente di test&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Implementare RMS nell'ambiente di produzione.</p></td>
<td style="border:1px solid black;"><p>&quot;Definizione dell'ambito dell'implementazione di RMS&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
</tbody>
</table>
  
<span id="BKMK_13"></span>
Distribuzione di RMS negli insiemi di strutture  
-----------------------------------------------
  
Utilizzare il seguente elenco di controllo per distribuire la directory principale di RMS in insiemi di strutture.
  
###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Passaggio</th>
<th>Riferimento</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Rivedere informazioni concettuali e di pianificazione.</p></td>
<td style="border:1px solid black;"><p>&quot;Preparazione di una distribuzione RMS&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Configurare le autorizzazioni obbligatorie in base al modello di trust specificato.</p></td>
<td style="border:1px solid black;"><p>&quot;Distribuzione di RMS negli insiemi di strutture&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Impostare gli attributi Active Directory appropriati per gli insiemi di strutture.</p></td>
<td style="border:1px solid black;"><p>&quot;Distribuzione di RMS negli insiemi di strutture&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a>.</p></td>
</tr>
</tbody>
</table>
  
<span id="BKMK_14"></span>
Elenchi di controllo per l'amministrazione di RMS  
-------------------------------------------------
  
Questa sezione fornisce elenchi di controllo per le seguenti attività di amministrazione:
  
-   [Implementare un modello di criteri per i diritti](#bkmk_15)  
-   [Distribuzione di un nuovo client RMS](#bkmk_16)  
-   [Aggiunta di un dominio utente trusted](#bkmk_17)  
-   [Aggiunta di un dominio di pubblicazione trusted](#bkmk_18)
  
Per ulteriori informazioni sulla gestione di RMS, vedere [Utilizzo di un server RMS](http://go.microsoft.com/fwlink/?linkid=42495) in questa documentazione.
  
<span id="BKMK_15"></span>
Implementare un modello di criteri per i diritti  
------------------------------------------------
  
Utilizzare la seguente lista di controllo per implementare un modello di criteri per i diritti.
  
###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Passaggio</th>
<th>Riferimento</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Rivedere i concetti appropriati.</p></td>
<td style="border:1px solid black;"><p>&quot;Modelli di criteri per i diritti&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42496">Guida di riferimento tecnico di RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Specificare il percorso del modello di criteri per i diritti.</p></td>
<td style="border:1px solid black;"><p>&quot;Per specificare il percorso dei modelli di criteri per i diritti&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42495">Utilizzo di un server RMS</a>.</p></td>
</tr>
<tr class="odd">
<td style="border:1px solid black;"><p>Creare il modello di criteri per i diritti.</p></td>
<td style="border:1px solid black;"><p>&quot;Creazione e modifica dei modelli di criteri per i diritti&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42495">Utilizzo di un server RMS</a>.</p>
<p>&quot;Per aggiungere un modello di criteri per i diritti&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42495">Utilizzo di un server RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Distribuire il modello di criteri per i diritti.</p></td>
<td style="border:1px solid black;"><p>&quot;Distribuzione dei modelli di criteri per i diritti&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42495">Utilizzo di un server RMS</a>.</p></td>
</tr>
</tbody>
</table>
  
<span id="BKMK_16"></span>
Distribuzione di un nuovo client RMS  
------------------------------------
  
Utilizzare la seguente lista di controllo per distribuire una nuova versione del client RMS.
  
###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Passaggio</th>
<th>Riferimento</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Rivedere i concetti appropriati.</p></td>
<td style="border:1px solid black;"><p>&quot;Pianificazione della distribuzione dei client&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42494">Distribuzione di un sistema RMS</a></p>
<p>&quot;Esclusione di versioni dell'archivio protetto&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42495">Utilizzo di un server RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Per imporre l'aggiornamento di tutti i client alla versione più recente del client, escludere la versione scaduta dell'archivio protetto.</p></td>
<td style="border:1px solid black;"><p>&quot;Per escludere versioni dell'archivio protetto&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42495">Utilizzo di un server RMS</a>.</p></td>
</tr>
</tbody>
</table>
  
<span id="BKMK_17"></span>
Aggiunta di un dominio utente trusted  
-------------------------------------
  
Utilizzare la seguente lista di controllo per aggiungere un dominio utente trusted.
  
###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Passaggio</th>
<th>Riferimento</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Rivedere i concetti appropriati.</p></td>
<td style="border:1px solid black;"><p>&quot;Domini di pubblicazione trusted&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42496">Guida di riferimento tecnico di RMS</a>.</p>
<p>&quot;Aggiunta e rimozione di domini di pubblicazione trusted&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42495">Utilizzo di un server RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Ottenere il certificato concessore di licenze server del dominio utenti che si desidera aggiungere. È necessario che tale informazione venga fornita dall'amministratore dell'installazione da ritenere attendibile. Aggiungere quindi il dominio utenti all'installazione.</p></td>
<td style="border:1px solid black;"><p>&quot;Per aggiungere un dominio di pubblicazione trusted&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42495">Utilizzo di un server RMS</a>.</p></td>
</tr>
</tbody>
</table>
  
<span id="BKMK_18"></span>
Aggiunta di un dominio di pubblicazione trusted  
-----------------------------------------------
  
Utilizzare la seguente lista di controllo per aggiungere un dominio di pubblicazione trusted.
  
###  

<p> </p>
<table style="border:1px solid black;">
<colgroup>
<col width="50%" />
<col width="50%" />
</colgroup>
<thead>
<tr class="header">
<th>Passaggio</th>
<th>Riferimento</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td style="border:1px solid black;"><p>Rivedere i concetti appropriati.</p></td>
<td style="border:1px solid black;"><p>&quot;Domini di pubblicazione trusted&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42496">RMS Technical Reference</a>.</p>
<p>&quot;Aggiunta e rimozione di domini di pubblicazione trusted&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42495">Utilizzo di un server RMS</a>.</p></td>
</tr>
<tr class="even">
<td style="border:1px solid black;"><p>Ottenere il certificato concessore di licenze server crittografato e la chiave privata del dominio di pubblicazione che si desidera aggiungere, quindi aggiungere tale dominio all'installazione.</p></td>
<td style="border:1px solid black;"><p>&quot;Per aggiungere un dominio di pubblicazione trusted&quot; in <a href="http://go.microsoft.com/fwlink/?linkid=42495">Utilizzo di un server RMS</a>.</p></td>
</tr>
</tbody>
</table>
