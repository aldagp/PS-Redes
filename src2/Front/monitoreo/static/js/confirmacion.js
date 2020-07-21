function confirmarEliminacion(id){
Swal.fire({
    title: '¿Estas seguro?',
    text: "Se eliminara el registro",
    icon: 'warning',
    showCancelButton: true,
    confirmButtonColor: '#3085d6',
    cancelButtonColor: '#d33',
    confirmButtonText: 'Sí, eliminar',
    cancelButtonText: 'Cancelar'
  }).then((result) => {
    if (result.value) {
      Swal.fire(
        //redirigir al usuario
        window.location.href= "/eliminarAdminServ/"+id+"/"
      )
    }
  })
}