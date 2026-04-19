var u = function (e) {
    var a = 0xedb88320;
    var r, c, d = 256;
    var s = [];

    for (; d--; s[d] = r >>> 0) {
        c = 8;
        r = d;
        for (; c--;) {
            if (1 & r) {
                r = r >>> 1 ^ a
            } else {
                r = r >>> 1
            }
        }
    }

    return function (e) {
        if ("string" == typeof e) {
            var r = 0;
            var c = -1;
            for (; r < e.length; ++r)
                c = s[255 & c ^ e.charCodeAt(r)] ^ c >>> 8;
            return -1 ^ c ^ a
        }
        for (; r < e.length; ++r)
            c = s[255 & c ^ e[r]] ^ c >>> 8;
        return -1 ^ c ^ a
    }
}()

console.log(u("I38rHdgsjopgIvesdVwgIC+oIELmBZ5e3VwXLgFTIxS3bqwErFeexd0ekncAzMFYnqthIhJeSnMDKutRI3KsYorWHPtGrbV0P9WfIi/eWc6eYqtyQApPI37ekmR6QL+5Ii6sdneeSfqYHqwl2qt5B0DBIx+PGDi/sVtkIxdsxuwr4qtiIhuaIE3e3LV0I3VTIC7e0utl2ADmsLveDSKsSPw5IEvsiVtJOqw8BuwfPpdeTFWOIx4TIiu6ZPwrPut5IvlaLbgs3qtxIxes1VwHIkumIkIyejgsY/WTge7eSqte/D7sDcpipedeYrDtIC6eDVw2IENsSqtlnlSuNjVtIvoekqt3cZ7sVo4gIESyIhE8HfquIxhnqz8gIkIfoqwkICZWG73sdlOeVPw3IvAe0fged0utIi5s3MV92utAIiKsidvekZNeTPt4nAOeWPwEIvSpaAAedqwXp9gsfqw+I3lrIxE5Luwwaqw+rekhZANe1MNe0Pw9ICNsVLoeSbIFIkosSr7sVnFiIkgsVVtMIiudqqw+tqtWI30e3PwIIhoe3ut1IiOsjut3wutnsPwXICclI3Ir27lk2I5e1utCIES/IEJs0PtnpYIAO0JeYfD1IErPOPtKoqw3I3OexqtWQL5eizJs1bEyIEJekd/skPtsnPwqIvOejqwiIk6ekoLeIvKeYBAeWVtSI3OsxutfJdYqIEi+Ik/eiz0sT/dsf00eSPwmIhEMIhihpVweI3PUIk6eW0kzLFgekPwlIxh0qqwQBngeieNsxVtNGqwaIxkUIi4ymPtLeqtgIxgefW5sxVw+rVt8"))