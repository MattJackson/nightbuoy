export const themes = [
 {id:'light',name:'NightBuoy Light',description:'Bright, clear surfaces with a blue accent.'},
 {id:'dark',name:'NightBuoy Dark',description:'Soft charcoal with comfortable contrast.'},
 {id:'midnight',name:'NightBuoy Midnight',description:'Deep navy with luminous cyan details.'},
 {id:'paper',name:'NightBuoy Paper',description:'Warm ivory, quiet browns and serif headings.'},
 {id:'contrast',name:'NightBuoy High Contrast',description:'Black, white and yellow with strong outlines.'},
] as const;
export type ThemeId=typeof themes[number]['id'];
export function themeId(value:string|null):ThemeId{return themes.some(t=>t.id===value)?value as ThemeId:'light';}
export type Branding={name:string;home:string;tagline:string;logo?:string;favicon?:string;css?:string;links:{label:string;href:string}[]};
export const defaultBranding:Branding={name:'NightBuoy',home:'/',tagline:'Community-owned conversations.',logo:'/nightbuoy.svg',favicon:'/nightbuoy.svg',links:[]};
