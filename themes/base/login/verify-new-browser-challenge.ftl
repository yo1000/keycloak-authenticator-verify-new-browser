<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle",realm.name)}
    <#elseif section = "header">
        ${msg("loginTitleHtml",realm.name)}
    <#elseif section = "form">
        <div id="kc-totp-login-form" class="${properties.kcFormClass!}">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <p for="totp" class="${properties.kcLabelClass!}">
                        Confirmation email has been sent to your registered email address because you are logging in with a new browser.
                        Please click on the link in the email to complete your login.
                    </p>
                </div>
            </div>
        </div>
    </#if>
</@layout.registrationLayout>