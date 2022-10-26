@echo off
set man_txt=dtxt(b'H4sIAPdpWWMC/5WV8W8bNRTHf75J+x/8YyvUSNsq+AmkkXVrtaBGaxBIVYXcO1/OxGcb27dc+AkE/FDasoKKkFilKoJpEWxjaEibCKX/TO8u/MS/gM9Oc07aTjRSktP7fvze83t+voWF//m5emX9zmprdQO0PZ9AGXlvvwPMgyOg+0j0SmGpfFARpm1HTUvlwzUktOiahWMHMuGcCQUEiplCYC7AEm4SBKDvIymBz6gSjMy765G7votVBJZi6EtwJpKkkJfsGsUcSoUciahSaGCpoOhdvbJwiaq831ppbACYeKUHmChWg1EHrC8vNZrXNkD+YO/k74fZ8a/57st/9p/lx5/lfwyzV6+K/UH2577+/fevnezbo5Phz6P+zqj/KPtqkH23M/ryx/zgSb71WBuLF8NieJgf7GZf9yfhOqhn4t1FvSZUfvTm4kxEUPw+vI/j4ounZdRBP98+BMUvP2QPfho9e54dfQ/yna1sb7d4/Hz08sXo6InVQH74qDjYHh0/LAbbJ8f9/PPfiqdbM7G70oTuSlJDKZqYSWDMtwQu+9BgMDDFtyKyItU95TCYmLmxcn1UGL1Re6u2OFFsDJkEbGKKjCnugQgRPrF+GtuwSHYUq8yJwsQI9QjSNgK3sEC+YqIHWsyIE1JdzCnGiARzm5jOO3h6MR9zZ01aLRLowjWiqqBe/jrXFccS3xbDFwjqKQkxqbx8YpSlFKvqtGB7WDAhoAVlZyKENuBtTAPQFKwcsUqjlbbG/A5SoM4o1SlVXU3HsThhwum28o29xRQkdRbHkLpnQY+HkW8u39UeY66Tr0TM7Vr9z2iI23agOVQKCVqdG2WgpjWDui3DTZ1pHRI/IVCXrSo+s7u8t9q8A4M2qvIPNm3+AVY6Dg0227WPpaOmZ2T9dXaPKj01ff9I2/wav8wNArS/8eR6eqoBRV3P9taWxhnx8mKZ0J6hy86WcEe31nNIO5gumRJLnl6oH2D6RgPM5d8MRrt78zPwmEW0QmcIOibKvb82w8ibvaiW7fi6EC+lU+5dBkUAVqg5wA5lHZU39FRIs1WHhMnZGp5ey9OYWzyLTJet9ORs83wn4/3JiHXPJ9y0qyCXPh/XtbPIQyQ0+ZAQhEzEUE2p3LwKOTpfY1OiHSwWhhLNguE0eDshZIrA69cWFjdKaIUqRMB7kCZwGjEvCExvXAeQY+BH8WV2/B9NLGyalAgAAA==')

if "%1"=="" goto show_man

:show_man_search
echo %man_txt% | p %~dp0Lib\xtools_exec.py -x -e stdout | findstr /i %1
goto end

:show_man
echo %man_txt% | p %~dp0Lib\xtools_exec.py -x -e stdout
goto end

:end
set man_txt=
@echo on