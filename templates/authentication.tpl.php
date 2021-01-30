<?php $this->data['pagetitle'] = $this->t('{webauthn:webauthn:page_title}'); ?>

<?php ob_start(); ?>
    <link rel="stylesheet" type="text/css" href="<?php echo htmlspecialchars(SimpleSAML\Module::getModuleUrl('webauthn/')); ?>assets/css/webauthn.css" />
    <meta name="frontendData" id="frontendData" content="<?php echo htmlspecialchars($this->data['frontendData']); ?>" />
 <?php $html = ob_get_contents(); ob_end_clean(); $this->data['head'] = $html; ?>
<?php $this->includeAtTemplateBase('includes/header.php'); ?>

    <h1><?php echo htmlspecialchars($this->t('{webauthn:webauthn:heading1}')); ?></h1>
    <?php if((isset($this->data['authURL'])?((is_array($this->data['authURL']) || $this->data['authURL'] instanceof Countable)?count($this->data['authURL']):strlen($this->data['authURL'])):0) > 0): ?>
        <form id='authform' method='POST' action='<?php echo $this->data['authURL']; ?>'>
            <input type='hidden' id='resp' name='response_id' value='0'/>
            <input type='hidden' id='data' name='attestation_client_data_json' value='nix'/>
            <input type='hidden' id='authdata' name='authenticator_data' value='mehrnix'/>
            <input type='hidden' id='sigdata' name='signature' value='evenmorenix'/>
            <input type='hidden' id='data_raw_b64' name='client_data_raw' value='garnix'/>
            <input type='hidden' id='type' name='type' value='something'/>
            <input type='hidden' id='operation' name='operation' value='AUTH'/>
            <button type='button' id='authformSubmit'><?php echo htmlspecialchars($this->t('{webauthn:webauthn:authTokenButton}')); ?></button>
        </form>
    <?php endif; ?>
    <script src="<?php echo htmlspecialchars(SimpleSAML\Module::getModuleUrl('webauthn/')); ?>assets/js/webauthn.js"></script>
    <script src="<?php echo htmlspecialchars(SimpleSAML\Module::getModuleUrl('webauthn/')); ?>assets/js/authentication.js"></script>

<?php $this->includeAtTemplateBase('includes/footer.php'); ?>
