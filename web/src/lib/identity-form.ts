// The identity vault enforces the same limits before encrypting private keys.
export const MIN_PASSPHRASE_LENGTH=20;
export const MAX_PASSPHRASE_LENGTH=1024;
export function passphraseIssue(password:string,confirmation:string):string{
 if(password.length<MIN_PASSPHRASE_LENGTH)return password.length?`${MIN_PASSPHRASE_LENGTH-password.length} more characters needed (at least ${MIN_PASSPHRASE_LENGTH} total).`:`Enter a passphrase of at least ${MIN_PASSPHRASE_LENGTH} characters.`;
 if(password.length>MAX_PASSPHRASE_LENGTH)return `Use no more than ${MAX_PASSPHRASE_LENGTH} characters.`;
 if(!confirmation)return 'Repeat your passphrase to confirm it.';
 if(password!==confirmation)return 'The two passphrases do not match.';
 return '';
}
