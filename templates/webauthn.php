<?php $this->data['pagetitle'] = $this->t('{webauthn:webauthn:page_title}'); ?>

<?php ob_start(); ?>
    <link rel="stylesheet" type="text/css" href="<?php echo htmlspecialchars(SimpleSAML\Module::getModuleUrl('webauthn/')); ?>assets/css/webauthn.css" />
    <meta name="frontendData" id="frontendData" content="<?php echo htmlspecialchars($this->data['frontendData']); ?>" />
 <?php $html = ob_get_contents(); ob_end_clean(); $this->data['head'] = $html; ?>
<?php $this->includeAtTemplateBase('includes/header.php'); ?>


    <h1><?php echo htmlspecialchars($this->t('{webauthn:webauthn:heading1}')); ?></h1>
    <h2><?php echo htmlspecialchars($this->t('{webauthn:webauthn:accountEnabled}')); ?></h2>
    <?php if((isset($this->data['FIDO2Tokens'])?((is_array($this->data['FIDO2Tokens']) || $this->data['FIDO2Tokens'] instanceof Countable)?count($this->data['FIDO2Tokens']):strlen($this->data['FIDO2Tokens'])):0) > 0): ?>
        <div id="currentTokens">
            <span id='tokencaption'><?php echo htmlspecialchars($this->t('{webauthn:webauthn:tokenList}')); ?></span>
            <ul>
                <?php foreach($this->data['FIDO2Tokens'] as $index => $this->data['token']): ?>
                    <?php if($this->data['FIDO2AuthSuccessful'] == false or $this->data['FIDO2AuthSuccessful'] != $this->data['token'][0]): ?>
                        <li class='othertoken'><?php echo htmlspecialchars($this->data['token'][3]); ?></li>
                    <?php else: ?>
                        <li class='currenttoken'><?php echo htmlspecialchars($this->data['token'][3]); ?> <?php echo htmlspecialchars($this->t('{webauthn:webauthn:currentToken}')); ?></li>
                    <?php endif; ?>
                <?php endforeach;?>
            </ul>
        </div>
    <?php endif; ?>
    <?php if((isset($this->data['regURL'])?((is_array($this->data['regURL']) || $this->data['regURL'] instanceof Countable)?count($this->data['regURL']):strlen($this->data['regURL'])):0) > 0): ?>
        <form id='regform' method='POST' action='<?php echo $this->data['regURL']; ?>'>
            <input type='hidden' id='resp' name='response_id' value='0'/>
            <input type='hidden' id='data' name='attestation_client_data_json' value='nix'/>
            <input type='hidden' id='attobj' name='attestation_object' value='mehrnix'/>
            <input type='hidden' id='type' name='type' value='something'/>
            <input type='hidden' id='operation' name='operation' value='REG'/>
            <button type='button' id='regformSubmit'><?php echo htmlspecialchars($this->t('{webauthn:webauthn:newTokenButton}')); ?></button>
            <?php echo htmlspecialchars($this->t('{webauthn:webauthn:newTokenName}')); ?>
            <input type='text' id='tokenname' name='tokenname' size='40'
                value='<?php echo htmlspecialchars($this->t('{webauthn:webauthn:newTokenDefaultName}')); ?> <?php echo htmlspecialchars((new DateTime("now"))->format('Y-m-d')); ?>' />
        </form>
        <div class='space'></div>
        <?php if((isset($this->data['FIDO2Tokens'])?((is_array($this->data['FIDO2Tokens']) || $this->data['FIDO2Tokens'] instanceof Countable)?count($this->data['FIDO2Tokens']):strlen($this->data['FIDO2Tokens'])):0) > 0): ?>
            <?php foreach($this->data['FIDO2Tokens'] as $index => $this->data['token']): ?>
                <?php if($this->data['FIDO2AuthSuccessful'] != $this->data['token'][0]): ?>
                    <form class='deleteform' id='delete-<?php echo htmlspecialchars($index); ?>' method='POST' action='<?php echo $this->data['delURL']; ?>'>
                        <input type='hidden' id='credId-<?php echo htmlspecialchars($index); ?>' name='credId' value='<?php echo htmlspecialchars($this->data['token'][0]); ?>'/>
                        <button type='submit' id='submit-<?php echo htmlspecialchars($index); ?>' name='submit' value='DELETE'>
                            <?php echo htmlspecialchars($this->t('{webauthn:webauthn:removePrefix}')); ?> &quot;<?php echo htmlspecialchars($this->data['token'][3]); ?>&quot;
                        </button>
                    </form>
                <?php endif; ?>
            <?php endforeach;?>
            <div class='space'></div>
            <form id='nevermind' method='POST' action='<?php echo $this->data['delURL']; ?>'>
                <button type='submit' id='submit-nevermind' name='submit' value='NEVERMIND'>
                    <?php echo htmlspecialchars($this->t('{webauthn:webauthn:noChange}')); ?>
                </button>
            </form>
        <?php endif; ?>
    <?php endif; ?>
    <?php if((isset($this->data['authURL'])?((is_array($this->data['authURL']) || $this->data['authURL'] instanceof Countable)?count($this->data['authURL']):strlen($this->data['authURL'])):0) > 0): ?>
        <form id='authform' method='POST' action='<?php echo $this->data['authURL']; ?>'>
            <input type='hidden' id='resp' name='response_id' value='0'/>
            <input type='hidden' id='data_raw_b64' name='client_data_raw' value='garnix'/>
            <input type='hidden' id='data' name='attestation_client_data_json' value='nix'/>
            <input type='hidden' id='authdata' name='authenticator_data' value='mehrnix'/>
            <input type='hidden' id='sigdata' name='signature' value='evenmorenix'/>
            <!-- ignoring <input type='hidden' id='userhandle' name='userhandle' value='someuser'/> -->
            <input type='hidden' id='type' name='type' value='something'/>
            <input type='hidden' id='operation' name='operation' value='AUTH'/>
            <input type='checkbox' id='credentialChange' name='credentialChange'>
            <label for='credentialChange'>
                <?php if((isset($this->data['FIDO2Tokens'])?((is_array($this->data['FIDO2Tokens']) || $this->data['FIDO2Tokens'] instanceof Countable)?count($this->data['FIDO2Tokens']):strlen($this->data['FIDO2Tokens'])):0) < 2): ?>
                    <?php echo htmlspecialchars($this->t('{webauthn:webauthn:wantsAdd}')); ?>
                <?php else: ?>
                    <?php echo htmlspecialchars($this->t('{webauthn:webauthn:wantsModification}')); ?>
                <?php endif; ?>
            </label><br/>
            <button type='button' id='authformSubmit'><?php echo htmlspecialchars($this->t('{webauthn:webauthn:authTokenButton}')); ?></button>
        </form>
    <?php endif; ?>
    <script src="<?php echo htmlspecialchars(SimpleSAML\Module::getModuleUrl('webauthn/')); ?>assets/js/webauthn.js"></script>

<?php $this->includeAtTemplateBase('includes/footer.php'); ?>