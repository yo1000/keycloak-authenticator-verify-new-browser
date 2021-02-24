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
                        ${challengeVerifyNewBrowserBody}
                    </p>
                </div>
            </div>
        </div>
    </#if>
</@layout.registrationLayout>